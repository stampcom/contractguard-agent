#!/usr/bin/env python3
"""ContractGuard — a verifiable pre-send contract address guard agent.

ContractGuard verifies a destination contract address *before* any funds
are sent to it, and issues a signed, checkable attestation of its decision.

It was born from a real incident: funds were bridged to a mistyped Celer
cBridge address (one wrong tail). The address was empty, wallet previews
and simulations passed anyway, and the funds were unrecoverable. A plain
``eth_getCode`` check would have rejected that address instantly.

Pure Python 3 standard library only — no dependencies.

Usage:
    python3 agent.py check --address 0x... --chain 56 \
        [--expected-code-hash 0x...] [--rpc URL] [--task-id X]
    python3 agent.py serve --port 8787
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

# --------------------------------------------------------------------------
# Keccak-256 (pure Python; NOT hashlib.sha3_256 — different padding)
# --------------------------------------------------------------------------

_MASK64 = (1 << 64) - 1

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# Rotation offsets r[x][y]
_KECCAK_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

def _rotl64(value: int, shift: int) -> int:
    if shift == 0:
        return value & _MASK64
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f1600(state: list) -> None:
    """Keccak-f[1600] permutation, in place, on 25 64-bit lanes."""
    for rc in _KECCAK_RC:
        # Theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # Rho and Pi: B[y][2x+3y] = rot(A[x][y], r[x][y])
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(
                    state[x + 5 * y], _KECCAK_ROT[x][y]
                )
        # Chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = (
                    b[x + 5 * y]
                    ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
                ) & _MASK64
        # Iota
        state[0] ^= rc


def keccak256(data: bytes) -> bytes:
    """Return the Keccak-256 digest of ``data`` (original Keccak padding)."""
    rate = 136  # 1088-bit rate for Keccak-256
    state = [0] * 25

    # pad10*1 with Keccak domain byte 0x01
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0x00)
    padded.append(0x80)

    for block_start in range(0, len(padded), rate):
        block = padded[block_start:block_start + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:(i + 1) * 8], "little")
            state[i] ^= lane
        _keccak_f1600(state)

    out = bytearray()
    while len(out) < 32:
        for i in range(rate // 8):
            out.extend(state[i].to_bytes(8, "little"))
        if len(out) < 32:
            _keccak_f1600(state)
    return bytes(out[:32])


def keccak256_hex(data: bytes) -> str:
    """Return the Keccak-256 digest of ``data`` as a 0x-prefixed hex string."""
    return "0x" + keccak256(data).hex()


# --------------------------------------------------------------------------
# EIP-55 checksum addresses
# --------------------------------------------------------------------------

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def is_valid_address_format(address) -> bool:
    """True if ``address`` is a 0x-prefixed 40-hex-character string."""
    return isinstance(address, str) and bool(_ADDRESS_RE.match(address))


def to_checksum_address(address: str) -> str:
    """Return the EIP-55 checksummed form of ``address``."""
    if not is_valid_address_format(address):
        raise ValueError(f"invalid address format: {address!r}")
    lower = address[2:].lower()
    digest = keccak256(lower.encode("ascii")).hex()
    out = []
    for ch, h in zip(lower, digest):
        if ch in "abcdef" and int(h, 16) >= 8:
            out.append(ch.upper())
        else:
            out.append(ch)
    return "0x" + "".join(out)


def has_mixed_case(address: str) -> bool:
    body = address[2:]
    return any(c.islower() for c in body) and any(c.isupper() for c in body)


def is_valid_checksum(address: str) -> bool:
    """EIP-55 checksum validity. Single-case addresses carry no checksum."""
    if not is_valid_address_format(address):
        return False
    if not has_mixed_case(address):
        return True
    return to_checksum_address(address) == address


# --------------------------------------------------------------------------
# JSON-RPC client (urllib, stdlib only)
# --------------------------------------------------------------------------

DEFAULT_RPCS = {
    1: [
        "https://ethereum-rpc.publicnode.com",
        "https://cloudflare-eth.com",
        "https://eth.llamarpc.com",
    ],
    56: [
        "https://bsc-dataseed4.binance.org",
        "https://bsc-dataseed.binance.org",
        "https://bsc-dataseed3.binance.org",
    ],
}

RPC_TIMEOUT = 15


class RpcError(Exception):
    """Raised when a JSON-RPC call fails on every candidate endpoint."""


def _json_rpc_once(rpc_url: str, method: str, params: list, timeout: int):
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode("utf-8")
    req = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json",
                 "Accept-Encoding": "gzip",
                 "User-Agent": "ContractGuard/1.0 (+https://agentgames.zkverify.io)"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        if resp.headers.get("Content-Encoding") == "gzip":
            raw = gzip.decompress(raw)
        body = json.loads(raw.decode("utf-8"))
    if "error" in body and body["error"]:
        raise RpcError(f"{method} returned error: {body['error']}")
    if "result" not in body:
        raise RpcError(f"{method} returned no result: {body!r}")
    return body["result"]


def json_rpc(rpc_url: str, method: str, params: list, timeout: int = RPC_TIMEOUT):
    """Perform a JSON-RPC call against one endpoint (up to 3 attempts).

    Retries and gzip matter in practice: an ``eth_getCode`` response for a
    large contract is tens of kilobytes of hex, and flaky transports can
    truncate it; a JSON-RPC *error* response is not retried.
    """
    last_exc = None
    for attempt in range(3):
        try:
            return _json_rpc_once(rpc_url, method, params, timeout)
        except RpcError:
            raise
        except Exception as exc:  # noqa: BLE001 - transport errors are retried
            last_exc = exc
            if attempt < 2:
                time.sleep(1.0 * (attempt + 1))
    raise RpcError(f"{method} failed after 3 attempts: {last_exc}")


def rpc_call(chain_id: int, method: str, params: list, rpc_url: str = None):
    """Call ``method`` on the given chain, trying fallbacks in order."""
    if rpc_url:
        return json_rpc(rpc_url, method, params)
    candidates = DEFAULT_RPCS.get(chain_id)
    if not candidates:
        raise RpcError(
            f"no default RPC known for chain_id={chain_id}; pass --rpc URL"
        )
    errors = []
    for i, url in enumerate(candidates):
        if i:
            time.sleep(1.0)  # do not hammer the next endpoint either
        try:
            return json_rpc(url, method, params)
        except Exception as exc:  # noqa: BLE001 - collect and try next
            errors.append(f"{url}: {exc}")
    raise RpcError("all RPC endpoints failed: " + " | ".join(errors))


# --------------------------------------------------------------------------
# Decision engine
# --------------------------------------------------------------------------


def _check(name: str, passed: bool, reason: str, required: bool = True) -> dict:
    return {"name": name, "passed": bool(passed), "required": bool(required),
            "reason": reason}


def evaluate(address, chain_id, rpc_url=None, expected_code_hash=None,
             require_contract=True, rpc_fn=None):
    """Evaluate whether funds may be sent to ``address`` on ``chain_id``.

    Args:
        address: Destination address (any hex case; EIP-55 checked if
            mixed-case).
        chain_id: Expected chain id (int).
        rpc_url: Optional explicit JSON-RPC endpoint; defaults per chain.
        expected_code_hash: Optional 0x-prefixed Keccak-256 of the expected
            deployed bytecode. If given, the on-chain code hash must match.
        require_contract: If True (default), an empty code result rejects.
        rpc_fn: Optional callable ``rpc_fn(method, params) -> result`` used
            instead of the live JSON-RPC client (dependency injection for
            tests / offline callers).

    Returns:
        A decision dict with ``decision`` ("APPROVE"/"REJECT"), per-check
        results, the observed ``code_hash``/``code_size``, and an
        ``attestation`` (see :func:`build_attestation`).
    """
    checks = []
    code_hash = None
    code_size = None

    def call(method, params):
        if rpc_fn is not None:
            return rpc_fn(method, params)
        return rpc_call(chain_id, method, params, rpc_url=rpc_url)

    # 1. Address format -----------------------------------------------------
    fmt_ok = is_valid_address_format(address)
    checks.append(_check(
        "address_format", fmt_ok,
        "0x + 40 hex characters" if fmt_ok else f"malformed address: {address!r}",
    ))
    if not fmt_ok:
        return _finalize(address, chain_id, checks, code_hash, code_size)

    # 2. EIP-55 checksum (mixed-case only) ----------------------------------
    if has_mixed_case(address):
        cks_ok = is_valid_checksum(address)
        checks.append(_check(
            "eip55_checksum", cks_ok,
            "EIP-55 checksum valid" if cks_ok else "EIP-55 checksum INVALID",
        ))
    else:
        checks.append(_check(
            "eip55_checksum", True,
            "single-case address: no checksum embedded, nothing to verify",
        ))

    # 3-5 need the chain -----------------------------------------------------
    try:
        reported_chain_hex = call("eth_chainId", [])
        reported_chain = int(reported_chain_hex, 16)
        chain_ok = reported_chain == int(chain_id)
        checks.append(_check(
            "chain_id_matches", chain_ok,
            f"RPC reports chain {reported_chain}, expected {chain_id}"
            if chain_ok else
            f"RPC reports chain {reported_chain}, expected {chain_id} — WRONG CHAIN",
        ))

        code = call("eth_getCode", [address, "latest"])
        if not isinstance(code, str):
            raise RpcError(f"eth_getCode returned non-string: {code!r}")
        code_bytes = bytes.fromhex(code[2:]) if code not in ("0x", "") else b""
        code_size = len(code_bytes)
        code_hash = keccak256_hex(code_bytes) if code_bytes else None

        # 4. Code exists -----------------------------------------------------
        code_ok = code_size > 0
        if require_contract:
            checks.append(_check(
                "code_exists", code_ok,
                f"{code_size} bytes of code deployed"
                if code_ok else "no code at address (eth_getCode == '0x') — "
                "an empty address cannot be the intended contract",
            ))
        else:
            checks.append(_check(
                "code_exists", True,
                f"{code_size} bytes of code deployed (not required)",
                required=False,
            ))

        # 5. Expected code hash ---------------------------------------------
        if expected_code_hash:
            exp = expected_code_hash.lower()
            got = (code_hash or "").lower()
            hash_ok = bool(code_hash) and got == exp
            checks.append(_check(
                "code_hash_matches", hash_ok,
                "code hash matches expected"
                if hash_ok else
                f"code hash {got or 'null'} != expected {exp}",
            ))
        else:
            checks.append(_check(
                "code_hash_matches", True,
                "no expected code hash supplied, check skipped",
                required=False,
            ))
    except Exception as exc:  # noqa: BLE001 - RPC failure must REJECT, never approve
        checks.append(_check(
            "rpc_reachable", False, f"RPC failure, cannot verify: {exc}",
        ))

    return _finalize(address, chain_id, checks, code_hash, code_size)


def _finalize(address, chain_id, checks, code_hash, code_size) -> dict:
    required = [c for c in checks if c["required"]]
    decision = "APPROVE" if required and all(c["passed"] for c in required) else "REJECT"
    result = {
        "address": address.lower() if isinstance(address, str) else address,
        "chain_id": chain_id,
        "checks": checks,
        "code_hash": code_hash,
        "code_size": code_size,
        "decision": decision,
    }
    result["attestation"] = build_attestation(result)
    return result


# --------------------------------------------------------------------------
# Attestation + HMAC signing (Agent Games style)
# --------------------------------------------------------------------------


def canonical_json(obj) -> bytes:
    """Canonical JSON encoding: sorted keys, compact separators, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_response(body_bytes: bytes, secret: str) -> str:
    """Hex HMAC-SHA256 of ``body_bytes`` under ``secret``."""
    if isinstance(body_bytes, str):
        body_bytes = body_bytes.encode("utf-8")
    return hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()


def verify_signature(body_bytes: bytes, secret: str, signature: str) -> bool:
    """Constant-time check of an HMAC-SHA256 hex signature."""
    if not signature:
        return False
    expected = sign_response(body_bytes, secret)
    return hmac.compare_digest(expected, signature.strip().lower())


def build_attestation(decision_result: dict, task_id: str = None,
                      secret: str = None, timestamp_unix: int = None) -> dict:
    """Build the signed, checkable attestation for a decision.

    The statement is the canonical JSON of the public claims (task id,
    address, chain id, code hash, decision, checks summary, timestamp).
    ``statement_hash`` is the SHA-256 of that canonical JSON. If a secret
    is available (argument or ``AGENT_GAMES_SECRET`` env), an HMAC-SHA256
    signature over the statement hash is included.
    """
    if secret is None:
        secret = os.environ.get("AGENT_GAMES_SECRET")
    if timestamp_unix is None:
        timestamp_unix = int(time.time())
    statement = {
        "task_id": task_id,
        "address": decision_result.get("address"),
        "chain_id": decision_result.get("chain_id"),
        "code_hash": decision_result.get("code_hash"),
        "decision": decision_result.get("decision"),
        "checks": [
            {"name": c["name"], "passed": c["passed"]}
            for c in decision_result.get("checks", [])
        ],
        "timestamp_unix": timestamp_unix,
    }
    statement_hash = hashlib.sha256(canonical_json(statement)).hexdigest()
    attestation = {
        "statement": statement,
        "statement_hash": statement_hash,
    }
    if secret:
        attestation["signature"] = sign_response(
            statement_hash.encode("utf-8"), secret
        )
    return attestation


# --------------------------------------------------------------------------
# HTTP server mode
# --------------------------------------------------------------------------

_TASK_CACHE: dict = {}


def handle_task(task: dict) -> dict:
    """Handle one task dict, with idempotency by ``task_id``."""
    task_id = task.get("task_id")
    if task_id and task_id in _TASK_CACHE:
        return _TASK_CACHE[task_id]
    result = evaluate(
        task.get("address"),
        task.get("chain_id"),
        rpc_url=task.get("rpc_url"),
        expected_code_hash=task.get("expected_code_hash"),
    )
    # Re-issue the attestation bound to this task_id.
    result["attestation"] = build_attestation(result, task_id=task_id)
    result["task_id"] = task_id
    if task_id:
        _TASK_CACHE[task_id] = result
    return result


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep the server quiet
        pass

    def _send_json(self, status: int, obj: dict, raw_body: bytes = None):
        body = raw_body if raw_body is not None else canonical_json(obj)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        secret = os.environ.get("AGENT_GAMES_SECRET")
        if secret:
            self.send_header("x-agent-games-signature", sign_response(body, secret))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - http.server API
        if self.path.rstrip("/") in ("/health", ""):
            self._send_json(200, {"status": "ok", "agent": "contractguard"})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802 - http.server API
        if self.path.rstrip("/") not in ("/check", "/task"):
            self._send_json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        secret = os.environ.get("AGENT_GAMES_SECRET")
        if secret:
            sig = self.headers.get("x-agent-games-signature", "")
            if not verify_signature(raw, secret, sig):
                self._send_json(401, {"error": "bad or missing signature"})
                return
        try:
            task = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError):
            self._send_json(400, {"error": "invalid JSON body"})
            return
        try:
            result = handle_task(task)
        except Exception as exc:  # noqa: BLE001
            self._send_json(500, {"error": str(exc)})
            return
        self._send_json(200, result)


def serve(port: int) -> None:
    server = HTTPServer(("0.0.0.0", port), _Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="agent.py", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="verify one address and print the attestation")
    p_check.add_argument("--address", required=True)
    p_check.add_argument("--chain", required=True, type=int)
    p_check.add_argument("--expected-code-hash", default=None)
    p_check.add_argument("--rpc", default=None)
    p_check.add_argument("--task-id", default=None)

    p_serve = sub.add_parser("serve", help="run the HTTP task server")
    p_serve.add_argument("--port", type=int, default=8787)

    args = parser.parse_args(argv)

    if args.command == "serve":
        serve(args.port)
        return 0

    result = evaluate(
        args.address,
        args.chain,
        rpc_url=args.rpc,
        expected_code_hash=args.expected_code_hash,
    )
    result["attestation"] = build_attestation(result, task_id=args.task_id)
    result["task_id"] = args.task_id
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0 if result["decision"] == "APPROVE" else 2


if __name__ == "__main__":
    raise SystemExit(main())

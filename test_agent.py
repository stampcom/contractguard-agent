#!/usr/bin/env python3
"""Offline unit tests for ContractGuard (``python3 -m unittest -v``).

All decision-logic tests use a mock RPC function — no network is touched.
"""

import hashlib
import unittest

import agent


# A small blob of fake deployed bytecode.
FAKE_CODE = "0x6080604052348015600e575f5ffd5b50606380601a5f395ff3fe"
FAKE_CODE_HASH = agent.keccak256_hex(bytes.fromhex(FAKE_CODE[2:]))
REAL_CHAIN = 56


def make_rpc(code=FAKE_CODE, chain_id=REAL_CHAIN):
    """Return a mock rpc_fn(method, params) serving fixed answers."""

    def rpc_fn(method, params):
        if method == "eth_chainId":
            return hex(chain_id)
        if method == "eth_getCode":
            return code
        raise AssertionError(f"unexpected method {method}")

    return rpc_fn


class TestKeccak(unittest.TestCase):
    def test_empty_vector(self):
        self.assertEqual(
            agent.keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )

    def test_abc_vector(self):
        self.assertEqual(
            agent.keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )

    def test_is_not_sha3(self):
        # Keccak-256 and SHA3-256 differ only in padding — guard the mix-up.
        self.assertNotEqual(agent.keccak256(b"abc"), hashlib.sha3_256(b"abc").digest())

    def test_long_input(self):
        # Exercises multi-block absorption (>136 bytes).
        data = bytes(range(256)) * 2
        self.assertEqual(len(agent.keccak256(data)), 32)
        self.assertEqual(agent.keccak256(data), agent.keccak256(bytes(data)))


class TestEIP55(unittest.TestCase):
    # Official test addresses from the EIP-55 specification.
    CHECKSUMMED = [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ]
    LOWER = [
        "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
        "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359",
        "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb",
        "0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb",
    ]

    def test_checksum_roundtrip(self):
        for lower, summed in zip(self.LOWER, self.CHECKSUMMED):
            self.assertEqual(agent.to_checksum_address(lower), summed)

    def test_valid_checksums_accepted(self):
        for addr in self.CHECKSUMMED:
            self.assertTrue(agent.is_valid_checksum(addr), addr)

    def test_single_case_accepted(self):
        for addr in self.LOWER:
            self.assertTrue(agent.is_valid_checksum(addr), addr)
            self.assertTrue(agent.is_valid_checksum("0x" + addr[2:].upper()), addr)

    def test_invalid_checksum_rejected(self):
        # Flip the case of one letter in a checksummed address.
        addr = list(self.CHECKSUMMED[0])
        for i, ch in enumerate(addr):
            if ch.isalpha() and i > 2:
                addr[i] = ch.lower() if ch.isupper() else ch.upper()
                break
        self.assertFalse(agent.is_valid_checksum("".join(addr)))

    def test_format(self):
        self.assertTrue(agent.is_valid_address_format(self.LOWER[0]))
        self.assertFalse(agent.is_valid_address_format("0x123"))
        self.assertFalse(agent.is_valid_address_format(self.LOWER[0][2:]))
        self.assertFalse(agent.is_valid_address_format(None))


class TestEvaluate(unittest.TestCase):
    ADDR = "0x10ED43C718714eb63d5aA57B78B54704E256024E"

    def test_empty_code_rejects(self):
        result = agent.evaluate(self.ADDR, REAL_CHAIN, rpc_fn=make_rpc(code="0x"))
        self.assertEqual(result["decision"], "REJECT")
        self.assertIsNone(result["code_hash"])
        self.assertEqual(result["code_size"], 0)

    def test_code_present_and_chain_match_approves(self):
        result = agent.evaluate(self.ADDR, REAL_CHAIN, rpc_fn=make_rpc())
        self.assertEqual(result["decision"], "APPROVE")
        self.assertEqual(result["code_hash"], FAKE_CODE_HASH)

    def test_expected_hash_match_approves(self):
        result = agent.evaluate(
            self.ADDR, REAL_CHAIN, rpc_fn=make_rpc(),
            expected_code_hash=FAKE_CODE_HASH,
        )
        self.assertEqual(result["decision"], "APPROVE")

    def test_expected_hash_mismatch_rejects(self):
        result = agent.evaluate(
            self.ADDR, REAL_CHAIN, rpc_fn=make_rpc(),
            expected_code_hash="0x" + "00" * 32,
        )
        self.assertEqual(result["decision"], "REJECT")

    def test_chain_mismatch_rejects(self):
        result = agent.evaluate(
            self.ADDR, REAL_CHAIN, rpc_fn=make_rpc(chain_id=1),
        )
        self.assertEqual(result["decision"], "REJECT")
        chain_check = [c for c in result["checks"] if c["name"] == "chain_id_matches"][0]
        self.assertFalse(chain_check["passed"])

    def test_bad_checksum_rejects(self):
        bad = "0x10ed43C718714eb63d5aA57B78B54704E256024E"  # mangled case
        if agent.is_valid_checksum(bad):
            self.skipTest("constructed address accidentally has a valid checksum")
        result = agent.evaluate(bad, REAL_CHAIN, rpc_fn=make_rpc())
        self.assertEqual(result["decision"], "REJECT")

    def test_malformed_address_rejects_without_rpc(self):
        def boom(method, params):
            raise AssertionError("RPC must not be called for malformed addresses")

        result = agent.evaluate("0xnotanaddress", REAL_CHAIN, rpc_fn=boom)
        self.assertEqual(result["decision"], "REJECT")

    def test_rpc_failure_rejects(self):
        def dead(method, params):
            raise RuntimeError("connection refused")

        result = agent.evaluate(self.ADDR, REAL_CHAIN, rpc_fn=dead)
        self.assertEqual(result["decision"], "REJECT")


class TestAttestationAndHmac(unittest.TestCase):
    def test_sign_verify_roundtrip(self):
        body = b'{"task_id":"t1","address":"0xabc"}'
        sig = agent.sign_response(body, "s3cret")
        self.assertTrue(agent.verify_signature(body, "s3cret", sig))

    def test_tamper_detected(self):
        body = b'{"decision":"APPROVE"}'
        sig = agent.sign_response(body, "s3cret")
        self.assertFalse(agent.verify_signature(b'{"decision":"REJECT"}', "s3cret", sig))
        self.assertFalse(agent.verify_signature(body, "wrong-secret", sig))
        self.assertFalse(agent.verify_signature(body, "s3cret", ""))

    def test_canonical_attestation_stability(self):
        result = agent.evaluate(
            TestEvaluate.ADDR, REAL_CHAIN, rpc_fn=make_rpc(),
        )
        a1 = agent.build_attestation(result, task_id="t-stable",
                                     secret="k", timestamp_unix=1700000000)
        a2 = agent.build_attestation(result, task_id="t-stable",
                                     secret="k", timestamp_unix=1700000000)
        self.assertEqual(a1["statement_hash"], a2["statement_hash"])
        self.assertEqual(a1["signature"], a2["signature"])
        # The hash really is sha256 of the canonical statement JSON.
        self.assertEqual(
            a1["statement_hash"],
            hashlib.sha256(agent.canonical_json(a1["statement"])).hexdigest(),
        )

    def test_attestation_signature_is_hmac_of_statement_hash(self):
        result = agent.evaluate(TestEvaluate.ADDR, REAL_CHAIN, rpc_fn=make_rpc())
        att = agent.build_attestation(result, task_id="t", secret="k",
                                      timestamp_unix=1700000000)
        self.assertEqual(
            att["signature"],
            agent.sign_response(att["statement_hash"].encode("utf-8"), "k"),
        )

    def test_attestation_unsigned_without_secret(self):
        result = agent.evaluate(TestEvaluate.ADDR, REAL_CHAIN, rpc_fn=make_rpc())
        att = agent.build_attestation(result, task_id="t", secret=None,
                                      timestamp_unix=1700000000)
        # Only present if the environment happens to set AGENT_GAMES_SECRET.
        import os
        if not os.environ.get("AGENT_GAMES_SECRET"):
            self.assertNotIn("signature", att)


class TestHttpTaskHandling(unittest.TestCase):
    def setUp(self):
        agent._TASK_CACHE.clear()

    def test_idempotency_same_task_id(self):
        # Patch evaluate via a counting wrapper around the mock-backed call.
        original = agent.evaluate
        calls = {"n": 0}

        def counting(address, chain_id, **kwargs):
            calls["n"] += 1
            kwargs["rpc_fn"] = make_rpc()
            return original(address, chain_id, **kwargs)

        try:
            agent.evaluate = counting
            task = {"task_id": "idem-1", "address": TestEvaluate.ADDR,
                    "chain_id": REAL_CHAIN}
            first = agent.handle_task(task)
            second = agent.handle_task(dict(task))
        finally:
            agent.evaluate = original
        self.assertIs(first, second)
        self.assertEqual(calls["n"], 1)
        self.assertEqual(first["decision"], "APPROVE")


if __name__ == "__main__":
    unittest.main()

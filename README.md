# ContractGuard

**A wallet-safety AI agent that verifies a destination contract address *before*
any funds are sent — and issues a signed, checkable attestation of its decision.**

Most pre-send checks ask "does this transaction simulate OK?" ContractGuard asks
a more basic question first: **is there actually the right contract at the
address you are about to send to, on the chain you think you are on?**

Pure Python 3 standard library. No dependencies.

## Why this exists — a real incident

ContractGuard was born from a real loss. Funds were being bridged through
Celer cBridge, and the destination contract address was mistyped — a wrong
tail on an otherwise correct-looking address (`...6Bf0` instead of the
official `...1820`). The mistyped address was **empty**: no contract had ever
been deployed there.

Nothing caught it:

- the bridge simulation passed,
- the wallet preview passed,
- the transaction was signed and sent,

and the funds were lost and unrecoverable. Simulations and previews can happily
succeed against an empty address — they do not check that the intended contract
is *there*. A single `eth_getCode` call would have rejected that address in
milliseconds. That check, done rigorously and attested, is ContractGuard.

## Who it helps

Anyone — human or agent — about to send funds to a contract address:

- bridging through a bridge contract (the original incident),
- minting from a contract you were given a link to,
- approving/spending through a router or vault address pasted from a doc,
- an AI agent executing transactions autonomously, where no human eyeballs
  the destination at all.

## How it works

`evaluate(address, chain_id)` runs five checks:

| # | Check | What it catches |
|---|-------|-----------------|
| 1 | **Address format** — `0x` + 40 hex chars | truncated / malformed paste |
| 2 | **EIP-55 checksum** (mixed-case addresses only) | a single flipped character, which almost always breaks the checksum |
| 3 | **Chain ID matches** — the RPC endpoint must report the chain you asked for | right contract, wrong network |
| 4 | **Code exists** — `eth_getCode` must not be `0x` | empty / never-deployed / mistyped addresses |
| 5 | **Code hash matches** (when an expected hash is supplied) — Keccak-256 of the deployed bytecode must equal the expected value | a *different* contract sitting at that address |

**Decision rule:** `APPROVE` only if every required check passes. Anything
else — including an unreachable RPC — is a `REJECT`. An agent that cannot
verify must never approve.

### Attestation

Every decision is issued with an attestation: the canonical JSON (sorted
keys) of the public claims —

```json
{
  "task_id": "example-good",
  "address": "0x5427fefa711eff984124bfbb1ab6fbf5e3da1820",
  "chain_id": 1,
  "code_hash": "0xd2b0c127b5a063e6adb2049fd927777ec7d5344a44ffad27767e461acd55b499",
  "decision": "APPROVE",
  "checks": [{"name": "address_format", "passed": true}, "…"],
  "timestamp_unix": 1794678840
}
```

`statement_hash` is the SHA-256 of that canonical JSON. When the
`AGENT_GAMES_SECRET` environment variable is set, the attestation also
carries `signature` — an HMAC-SHA256 over the statement hash — and the HTTP
layer signs its responses (and verifies inbound signatures) with the same
secret, in the Agent Games style.

## Run it

### CLI

```bash
# Official Celer cBridge on Ethereum — expect APPROVE, exit code 0
python3 agent.py check --address 0x5427FEFA711Eff984124bFBB1AB6fbf5E3DA1820 --chain 1

# The mistyped, empty address — expect REJECT, exit code 2
python3 agent.py check --address 0x5427FEFA711Eff984124bFBB1AB6fbf5E3DA6Bf0 --chain 1

# PancakeSwap router on BSC, pinned to its expected code hash
python3 agent.py check --address 0x10ED43C718714eb63d5aA57B78B54704E256024E --chain 56 \
  --expected-code-hash 0x69aef35de7236f9ae83edadff736f01ea40edd8919b2e73d87dea5d3255b8c3e
```

Defaults: Ethereum uses public RPCs (publicnode first); BSC uses the official
Binance endpoints (`bsc-dataseed4` first, then `bsc-dataseed` /
`bsc-dataseed3`). Override with `--rpc URL`. Example tasks live in
[`examples/`](examples/).

### HTTP server (agent endpoint)

```bash
AGENT_GAMES_SECRET=your-secret python3 agent.py serve --port 8787
```

- `GET /health` → `{"status": "ok", "agent": "contractguard"}`
- `POST /check` or `POST /task` with
  `{"task_id": "…", "address": "0x…", "chain_id": 56, "expected_code_hash": "0x…"}`
  → the decision + attestation JSON.
- If `AGENT_GAMES_SECRET` is set, inbound requests must carry a valid
  `x-agent-games-signature` HMAC header (401 otherwise) and responses are
  signed with the same header. Repeated `task_id`s are idempotent: the same
  decision object is returned.

### Tests

```bash
python3 -m unittest -v   # 23 tests, fully offline (RPC is mocked)
```

The suite covers the pure-Python Keccak-256 against known vectors, EIP-55
against the official specification addresses, the decision engine (empty
code → REJECT; chain mismatch → REJECT; code-hash mismatch → REJECT), HMAC
sign/verify + tamper detection, attestation-hash stability, and task
idempotency.

## Verified live examples

Real runs of the CLI above against live public RPCs (November 2026):

```json
{"task_id": "example-good",  "address": "0x5427fefa711eff984124bfbb1ab6fbf5e3da1820",
 "chain_id": 1,  "decision": "APPROVE", "code_size": 20574,
 "code_hash": "0xd2b0c127b5a063e…55b499"}
```
Official Celer cBridge on Ethereum — deployed code present, checksum valid → **APPROVE**.

```json
{"task_id": "example-bad",   "address": "0x5427fefa711eff984124bfbb1ab6fbf5e3da6bf0",
 "chain_id": 1,  "decision": "REJECT",  "code_size": 0, "code_hash": null}
```
The mistyped address from the incident — `eth_getCode` is `0x` (and the
mistyped string's EIP-55 checksum is invalid) → **REJECT**. This is the exact
send ContractGuard exists to stop.

```json
{"task_id": "example-bsc",   "address": "0x10ed43c718714eb63d5aa57b78b54704e256024e",
 "chain_id": 56, "decision": "APPROVE", "code_size": 21936,
 "code_hash": "0x69aef35de7236f…5b8c3e"}
```
PancakeSwap router on BSC via the official Binance dataseed endpoints → **APPROVE**.

## zkVerify relevance

An attestation is a claim: *"for this address, on this chain, the deployed
code hashed to X, and my policy decision was APPROVE."* Today that claim is
only as good as your trust in the agent that signed it. That is exactly the
gap [zkVerify](https://zkverify.io) exists to close: the policy decision can
be expressed as a statement with public inputs — the address, the chain id,
the code hash, and the decision — proven (e.g. with a Groth16 proof over the
policy circuit) and attested through zkVerify's dedicated proof-verification
chain, instead of merely trusted. Anyone can then check that the decision
followed the committed policy, without seeing the agent's internals and
without re-running the RPC calls. "The agent said APPROVE" becomes "the
approval is on record, and it checks out."

ContractGuard was entered in the **zkVerify Agent Games** (Creator /
Wildcard tracks) — #AgentGames · @ZKVProtocol.

## Limitations

ContractGuard checks the **existence and identity** of the code at an
address — it does **not** judge whether that code is honest. A deployed scam
contract has code, a valid checksum, and a stable code hash; pair
ContractGuard with audits, allowlists, and simulation for defence in depth.
It verifies at the moment of the check; a proxy contract's implementation
can change afterwards.

## Layout

```
agent.py        the agent (Keccak-256, EIP-55, JSON-RPC, decision engine,
                attestation/HMAC, CLI + HTTP server) — stdlib only
test_agent.py   offline unittest suite
examples/       sample task JSON files (good, typo'd, BSC)
```

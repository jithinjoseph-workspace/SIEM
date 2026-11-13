# siem-authd: what siem-api needs (replaced 2026-11-12)

siem-api used three things from `siem-authd`. Agents no longer enroll through it (they enroll
over HTTPS through provigil-gateway), so nothing else is needed. The new code lives in siem-api.

## 1. Group limit

An agent may be in at most **128** groups (the agent database limit; was 256 until 13 Nov 2026). `groups::resolve` refuses more with
`Maximum multigroup reached: Limit is 128`.

## 2. A new key for an enrolling agent

Input: the agent ID siem-api chose, the agent name, its address. Output: a key entry with that
ID, name and address and a **new random key** (64 hex characters, from `KeyStore::generate_raw_key`
in provigil-crypto), added to the in-memory key store. The caller removes any old key of the
same ID first (it already does). The ID is never generated here: siem-api always gives it.

## 3. The text reply

The enrollment answer carried `authd_response`, the old protocol's one-line reply repeating ID,
name, address and key. No agent, script or gateway reads it (checked 2026-11-12: provigil-agent,
siem-agent-linux, install.sh, install-provigil.ps1, provigil-gateway). It is dropped; the JSON
fields `agent_id`, `agent_name`, `agent_ip` and `raw_key` carry the same values.

## Tests

- 128 groups pass, 129 are refused with the message above.
- The new key has the given ID, name and address, 64 hex characters, is in the store, and two
  calls give different keys.

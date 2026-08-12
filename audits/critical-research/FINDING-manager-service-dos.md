# Bug Report — Guardian Manager Service: unverified signature aggregation enables a single guardian to permanently block Dogecoin/XRPL releases

## Title
Manager Service aggregates unverified, unbound partial signatures — a single guardian can poison signature and DB state to permanently block all UTXO/XRPL fund releases (liveness DoS)

## Description
The guardian node's **Manager Service** collects the M-of-N partial signatures that authorize releasing custodied **Dogecoin (P2SH)** and **XRPL (multisig)** funds. When it ingests a peer's gossiped `ManagerTransaction`, it (1) stores the partial signatures **without verifying them**, (2) does **not** bind the claimed `SignerIndex` to the guardian that actually signed the gossip envelope, and (3) does **not** validate that the message's `VaaHash`/`VaaId` correspond to a real VAA before using them as database keys. Because signature slots are filled first-write-wins, a **single malicious guardian** can front-run honest signatures with garbage under *every* signer index and overwrite the `VaaId → hash` index, so the externally-assembled multisig transaction is invalid and rejected on-chain. The result is a **network-wide, persistent denial of service** on UTXO/XRPL releases: custodied funds cannot be released. No funds are stolen (the destination-chain multisig independently verifies signatures), but the release path is durably bricked until the aggregation logic is fixed and the poisoned DB state is cleared.

---

## Severity
**High (temporary/persistent freezing of a bridge function's liveness).**

Honest caveats a triager will weigh (disclosed in good faith):
- **Requires a guardian.** The p2p layer (`processSignedManagerTransaction`) only accepts `ManagerTransaction` gossip signed by a guardian key, so the attacker must control a guardian — a privileged, semi-trusted role — and is cryptographically identifiable (removable via governance). This typically caps the rating at High/Medium rather than Critical.
- **No theft.** Funds are never moved to an attacker; the on-chain M-of-N multisig rejects the invalid transaction. Impact is liveness, not loss.
- **Recoverable.** A client fix plus clearing the poisoned DB entries restores service.
- **Deployment status.** At the time of review `KnownManagerEmitters` / `KnownXRPLSequencer` are **empty on mainnet** (`sdk/mainnet_consts.go`); the feature is configured only on devnet. If it is not yet protecting mainnet TVL, program scope may treat this as pre-production. Verify current deployment before submitting.

---

## Affected code
- `node/pkg/manager/manager.go`
  - `handleIncomingTransaction` (≈ L311–351): stores incoming partial signatures with no signature verification; validates `SignerIndex < managerSet.N` but never checks that the gossip-envelope guardian equals the claimed `SignerIndex`; carries a standing `SECURITY:` comment acknowledging (1) invalid sigs stored permanently, (2) signer-index spoofing, (3) metadata poisoning.
  - `storeSignature` (≈ L428–515): first-write-wins per `SignerIndex` (`if _, alreadyHave := aggTx.Signatures[sig.SignerIndex]; alreadyHave { return }`); first message for a `VAAHash` fixes `ManagerSetIndex`; a later signature with a different index is dropped as "mismatched manager set index".
- `node/pkg/db/manager.go`
  - Keys `MANAGER:SIG:V1:<hex(VaaHash)>` and `MANAGER:IDX:V1:<VaaId>` are built from attacker-controlled, unvalidated `VaaHash`/`VaaId` (`StoreAggregatedTransaction`).
- `node/pkg/p2p/p2p.go`
  - `processSignedManagerTransaction` (≈ L1775): authenticates the envelope as a guardian but does **not** constrain the inner `SignerIndex`/`VaaHash`/`VaaId`.

---

## Root cause
Three compounding gaps on the ingest path:
1. **No signature verification on ingest.** Partial signatures are stored as opaque bytes and never checked against the computed sighash for the claimed signer's public key.
2. **`SignerIndex` is not bound to the sender.** The envelope proves *a* guardian sent the message, but any guardian can claim *any* signer slot for *any* other guardian.
3. **`VaaHash`/`VaaId` are unvalidated.** They are used directly as database keys with no check that they correspond to a locally-known signed VAA.

Combined with first-write-wins storage, these let one guardian occupy and corrupt the entire aggregation state for a release.

---

## Attack scenario (step by step)
Precondition: the attacker controls one guardian key (passes the p2p envelope check). Target: a pending UTXO/XRPL release with VAA hash `H`, requiring M-of-N manager signatures.

1. The attacker observes (or anticipates) the release VAA `H`.
2. For each signer index `i = 0 … N-1`, the attacker broadcasts a signed `ManagerTransaction` with `VaaHash = H`, `SignerIndex = i`, and **garbage `Signatures`** — racing ahead of the honest guardians' real partial signatures.
3. Every honest node accepts these (envelope is a valid guardian; `SignerIndex < N`) and stores them first-write-wins. When the honest signature for index `i` arrives later, it is dropped ("already have signature from signer").
4. Once M garbage slots are filled, the aggregation reports "enough signatures". The **external assembler** reads these signatures, builds the multisig transaction, and broadcasts it — the on-chain multisig **rejects it** (invalid signatures).
5. Optionally, the attacker also submits a real `VaaId` with a bogus `VaaHash`, overwriting `MANAGER:IDX:V1:<VaaId>` so `GetPendingTransactionByID` returns attacker garbage; and floods unique `VaaHash` values to grow the DB.
6. Because invalid signatures are stored persistently, the release for `H` stays bricked until operators patch the client and clear DB state.

Escalation ceiling (verified): the manager service is only a *signature collector*; its output is consumed solely by the destination-chain M-of-N multisig, which verifies every signature against the funds' own script. No collector corruption can produce a *valid* signature authorizing a different payout (confirmed by a payout-binding property test over ~25k adversarial mutations). The manager DB is namespace-isolated (`MANAGER:` prefix) from signed VAAs (`signed/`), governor (`GOV:`), and notary (`NOTARY:`), so poisoning cannot corrupt consensus/replay state. Impact is therefore strictly **liveness/DoS**, not theft.

---

## Impact
- **Persistent, network-wide denial of service** on Dogecoin/XRPL fund releases: custodied funds cannot be released while the poisoning persists.
- Secondary: `VaaId → hash` index corruption (wrong lookups) and unbounded database growth (storage pressure), both confined to the manager namespace.

---

## Proof of concept (included, passing)
A runnable Go PoC lives at `node/pkg/manager/poc_manager_dos_test.go`. It drives the **real**
`ManagerService.storeSignature` path with an in-memory `ManagerDB` and a pre-populated
`ManagerSetReader` cache (no Ethereum RPC needed), against a 2-of-3 Dogecoin manager set:

- `TestPoC_SignerIndexSpoofingCompletesAggregationWithGarbage` — one attacker identity fills all three
  signer slots with junk; the aggregation reports `IsComplete()` with zero valid signatures; a later
  honest signature for a poisoned slot is dropped (first-write-wins).
- `TestPoC_IndexPoisoningRedirectsByVaaID` — submitting a legitimate `VaaId` with a bogus `VaaHash`
  redirects `GetPendingTransactionByID(victimVaaId)` to the attacker's entry.
- `TestPoC_UnvalidatedVaaHashCreatesEntries` — 500 arbitrary `VaaHash` values create 500 DB entries
  (unbounded-growth primitive).

Run:
```
cd node && go test ./pkg/manager/ -run 'TestPoC_' -v
```
Result: all three pass.
```
--- PASS: TestPoC_SignerIndexSpoofingCompletesAggregationWithGarbage
--- PASS: TestPoC_IndexPoisoningRedirectsByVaaID
--- PASS: TestPoC_UnvalidatedVaaHashCreatesEntries
```
(The unrelated `TestGetManagerSet_Dogecoin_Index1` in the same package is a pre-existing live-RPC
integration test and fails only because the sandbox blocks the Sepolia endpoint.)

---

## Recommended remediation
1. **Verify partial signatures on ingest.** Before storing, verify each signature against the computed sighash(es) for the claimed signer's manager public key; drop the whole `ManagerTransaction` if any is invalid. Where the sighashes are not yet known (VAA not processed locally), hold signatures in a `PendingSignatures` buffer and verify them once the VAA is processed (the mitigation already sketched in the standing `SECURITY:` comment).
2. **Bind `SignerIndex` to the sender.** Reject a `ManagerTransaction` whose claimed `SignerIndex` does not correspond to the envelope guardian's own slot in the manager set.
3. **Validate `VaaHash`/`VaaId`.** Only create a DB entry for a `VaaHash`/`VaaId` that matches a locally-known, quorum-verified signed VAA; reject unknown identifiers to prevent index poisoning and storage exhaustion.
4. Consider replacing first-write-wins with verified-overwrite so a late honest signature can displace an earlier invalid one.

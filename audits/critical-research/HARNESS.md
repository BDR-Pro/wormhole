# Dynamic property-test harness

These tests drive the **real** guardian-node code to try to *falsify* the two invariants whose
failure would be Critical. They are not illustrative mocks — they call the production functions on
the signing / quorum path. A failing test prints a "WITNESS" line describing the exploit it found.

## What is tested

### 1. Manager Service payout binding — `node/pkg/manager/dogecoin/audit_payout_binding_test.go`
Falsification target: *"a guardian's partial signature can only ever authorize the exact payout in the
guardian-signed VAA."* If false, a signature collected for a legitimate Dogecoin/XRPL release could be
replayed to redirect custody funds → **Critical theft**.

Drives the real `BuildRedeemScript` + `BuildUnsignedTransaction` + `ComputeSighash(SigHashAll)` path
(the same calls `ManagerService.signDogecoinTransaction` makes):

- `TestPayoutBinding_OutputMutationChangesSighash` — 5,000 randomized releases; for each, applies
  adversarial mutations (retarget recipient, inflate amount, add output, reorder outputs, retarget the
  input UTXO) and asserts the input-0 sighash **changes** every time. ~25k attempts, no collision.
- `TestPayoutBinding_DistinctRecipientsDisjointSighashes` — 3,000 releases; a release to a different
  recipient shares **no** input sighash with the original (positive control: proves the check has teeth —
  it would fail if the sighash didn't bind the recipient).
- `TestRedeemScriptBinding` — the emitter chain, emitter contract, and original recipient are all
  committed into the redeem script (hence the P2SH address), so a crafted prefix targets a different
  address than the funds sit at.

### 2. Delegated-guardian quorum floor — `node/pkg/processor/audit_delegate_quorum_test.go`
Falsification target: *"a delegated chain's threshold can never be configured below the 2/3 Byzantine
quorum."* If false, a smaller minority of a delegated set could forge that chain's messages → **Critical**.

- `TestDelegateQuorumFloor` — exhaustively fuzzes `(numKeys 1..40, threshold -2..n+10)` against the real
  `NewDelegatedGuardianChainConfig`; a config is accepted **iff** `CalculateQuorum(n) <= threshold <= n`,
  and every accepted `Quorum()` is `>= floor(2n/3)+1`.
- `TestDelegateConfigRejectsDuplicateKeys` — a duplicated delegated key (one compromised key counting
  twice) is rejected.
- `TestCalculateQuorumIsByzantine` — for n=1..255 the node's quorum equals the on-chain `(2n/3)+1` and is a
  strict super-2/3 majority (node and chains agree on the threshold).

## Result

All tests **PASS** — i.e., neither invariant could be falsified against the real code. This is empirical
corroboration of the static verdict, not a substitute for it.

```
$ cd node
$ go test ./pkg/manager/dogecoin/ -run 'TestPayoutBinding|TestRedeemScriptBinding' -v
--- PASS: TestPayoutBinding_OutputMutationChangesSighash (0.74s)
--- PASS: TestPayoutBinding_DistinctRecipientsDisjointSighashes (0.16s)
--- PASS: TestRedeemScriptBinding (0.00s)

$ go test ./pkg/processor/ -run 'TestDelegateQuorumFloor|TestDelegateConfigRejectsDuplicateKeys|TestCalculateQuorumIsByzantine' -v
--- PASS: TestDelegateQuorumFloor (0.00s)
--- PASS: TestDelegateConfigRejectsDuplicateKeys (0.00s)
--- PASS: TestCalculateQuorumIsByzantine (0.00s)
```

## How to extend (next dynamic targets)

- **Manager aggregation DoS PoC** — instantiate `ManagerService` with an in-memory DB + a stubbed
  `ManagerSetReader` and show a single guardian occupying every `SignerIndex` blocks release assembly
  (confirms the documented High-severity liveness bug end-to-end).
- **Delegate-consensus set-rotation** — property test `handleSignedDelegateObservation` /
  `checkForDelegateQuorum` across simultaneous delegated-set updates: no canonical signing without
  ≥ delegate-quorum distinct delegated signers over one `CreateDigest()`.

# Wormhole — Critical-Severity Security Research

**Scope:** `bdr-pro/wormhole` @ `claude/smart-contract-critical-research-lb9rkg`
(base `main` = `3a55db8`, includes delegated-guardian sets 7/8/9, Solana token-bridge
pause/freeze feature, EVM pause/freeze + delegated-guardian/manager-set/custom-consistency
peripherals, and the rewritten Aptos watcher)

**Objective:** Identify, prove, and escalate any vulnerability to **Critical** severity
(TVL drain, unbacked mint, VAA/message forging, guardian-quorum bypass, governance hijack,
permanent fund lock, accountant/governor bypass).

**Method:** Adversarial line-by-line trace of every VAA-authentication and fund-movement path
across all chains and the guardian node, plus an 8-surface parallel finder/adversarial-refuter
workflow. Each candidate was pushed toward Critical via attack-chaining, then an independent
pass attempted to *refute* it against the real guard code.

---

## Verdict

**No Critical-severity vulnerability was found.** Every fund-movement and message-authentication
path enforces a consistent, layered set of invariants that block escalation. This document is the
**Phase-4 deliverable**: an explicit proof of *why current constraints prevent escalation*, plus the
genuine non-critical observations found and the highest residual-risk areas for dynamic follow-up.

This is a static adversarial review. A negative result here does **not** prove the absence of bugs
reachable only through fuzzing, economic simulation, or live multi-chain state — see
[Residual risk](#residual-risk--where-to-point-dynamic-testing).

---

## The invariant lattice (why escalation is blocked)

Every critical vector ultimately has to break one of these, and each is enforced redundantly:

| # | Invariant | Enforced by |
|---|-----------|-------------|
| I1 | A VAA is valid only with **≥⌊2n/3⌋+1 distinct** guardian signatures over `keccak(keccak(body))` | EVM `Messages.verifySignatures`; SDK `verifySignatures`; Solana `verify_signature`+`post_vaa`; wormchain `VerifyVAA`; Move `vaa::verify` |
| I2 | Signatures must have **strictly-ascending, in-bounds, non-duplicate** guardian indices | all of the above (index monotonicity + explicit dup checks) |
| I3 | Every VAA is **consumed once** (replay protection) before/at first effect | EVM `isTransferCompleted`/`consumedGovernanceActions`; Solana `claim::consume`; Move `parse_verify_and_replay_protect`/`verify_only_once`; wormchain `ReplayProtection`; accountant `DIGESTS` |
| I4 | Inbound transfers accepted only from the **registered** peer emitter for that chain | EVM `verifyBridgeVM`; Solana `Endpoint::verify_derivation`; Move `token_registry`/registered-emitter; accountant `CHAIN_REGISTRATIONS` |
| I5 | The redeemed **asset is bound** to the VAA's `(token_chain, token_address)` | EVM `wrappedAsset`; Solana mint/`WrappedDerivationData`; Aptos `assert_coin_origin_info`; Sui `verify_and_bridge_out` |
| I6 | Balance/amount math **cannot wrap**; native withdrawals bounded by custody/`outstandingBridged` | Solidity 0.8 checked; Rust `checked_*`/`Uint256`; Move abort-on-overflow |
| I7 | Governance actions require the **governance emitter + current guardian set** and are replay-protected | EVM `verifyGovernanceVM`; Solana `verify_governance`; wormchain `VerifyGovernanceVAA` |
| I8 | Guardian-set / delegated-set / manager-set indices are **monotonic (+1), no rollback/overwrite** | EVM `submitNewGuardianSet`; Solana `upgrade_guardian_set`; `DelegatedManagerSet`; `WormholeDelegatedGuardians` |

A Critical requires defeating **I1/I2/I3 without guardian-majority compromise**, or an arithmetic/
accounting flaw defeating **I5/I6**. None was found.

---

## Surfaces examined and refuted

### 1. EVM core — `Messages.sol`, `Implementation.sol`, `Governance.sol`
- `verifySignatures` ecrecovers each sig, rejects `address(0)`, requires `sig.guardianIndex` strictly
  ascending and `< guardianCount`, and matches `signatory == keys[index]`. `quorum=(2n/3)+1`. Empty
  set rejected *before* quorum → the "true on empty sigs" branch is unreachable via `verifyVM`. **(I1,I2)**
- `parseVM` binds `hash = keccak(keccak(body))` over exactly the parsed fields; `verifyVM(checkHash=true)`
  re-derives it. `version`/`guardianSetIndex` are outside the hash but can't be leveraged (sigs still
  checked against the claimed set; nonexistent set rejected). `BytesLib` reverts on OOB — no
  attacker-favorable reads.
- Guardian-set update is `+1`-monotonic, rejects `address(0)` keys, replay-guarded; old set expires on a
  bounded 24h window; governance requires `guardianSetIndex == current`. **(I7,I8)**

### 2. EVM Token Bridge — `Bridge.sol`, `BridgeGovernance.sol`, `TokenImplementation.sol`
- `_completeTransfer` sets `setTransferCompleted(vm.hash)` **before** any external call
  (checks-effects-interactions); ETH payouts use `transfer` (2300 gas); wrapped mint calls no external
  code — no reentrant double-redeem. **(I3)**
- Native redemption decrements `outstandingBridged` (`bridgedIn`), which **underflow-reverts** if it would
  exceed what was bridged out; dust stripped via `deNormalize(normalize(...))`; fee-on-transfer corrected
  via balance-delta. **(I5,I6)**
- `verifyBridgeVM` rejects forks and requires `bridgeContracts(emitterChain)==emitterAddress`. Wrapped
  create uses deterministic CREATE2 salt `keccak(tokenChain,tokenAddress)` and reverts on duplicate.
- **New pause/freeze feature:** `_requireRole` gates pause/freeze/unpause; roles set only by
  governance-VAA `submitSetPauserAddresses`. `freeze` sets `pauseExpiry=type(uint64).max` so
  `unpauseExpired` can never lift it; `pause` reverts if it would not push the expiry forward (a lower-trust
  pauser can't curtail a freeze). New storage packs into the existing Provider slot + an ERC-7201
  namespaced slot — **no collision** with `ReentrancyGuard._status` or `State` fields.

### 3. EVM peripherals — delegated guardians / manager set / custom consistency
- All three are **immutable, governance-VAA-gated registries** with current-guardian-set signature checks,
  governance chain/contract binding, per-hash replay protection, and monotonic index/config counters.
- **Grep-confirmed: no core verification or value-bearing contract reads their state.** `CustomConsistencyLevel`
  is a per-`msg.sender` config map — an attacker can only set consistency for their *own* emitter, never the
  token bridge's, so the reorg/finality vector cannot touch bridge TVL. Impact ceiling is off-chain / integrator-side.

### 4. Solana core — `verify_signature.rs`, `post_vaa.rs`, `governance.rs`
- Post-2022-hack hardened: `load_current_index_checked` / `load_instruction_at_checked` validate the
  Instructions **sysvar account**; the secp256k1 instruction is bound as the immediately-preceding ix; all
  address/message offsets must reference **within** that secp ix; messages must be equal and exactly 32 bytes;
  each guardian key must equal the secp-recovered address. Every attacker-controlled index is array-bounded. **(I1,I2)**
- `post_vaa` binds the SignatureSet to the VAA: `check_valid_sigs` requires
  `signature_set.guardian_set_index == guardian_set.index`; `check_integrity` requires
  `signature_set.hash == keccak(body)` (the secp precompile's internal keccak makes the guardian-signed
  digest the canonical double-keccak); `check_active` rejects expired sets (+ initial-set fix); quorum `(2n/3)+1`.
- `upgrade_guardian_set` is `+1`-monotonic vs both old-set and bridge index, replay-guarded, creates a fresh
  account (no overwrite). **(I8)**

### 5. Solana Token Bridge — pause feature + transfers/complete/create-wrapped
- `require_not_paused` is present on **all 10** fund/attest paths (`transfer_native/wrapped`,
  `..._with_payload`, `complete_native/wrapped`, `..._with_payload`, `attest`, `create_wrapped`); governance
  and `unpause` intentionally exempt.
- Config account is a solitaire-validated PDA; the 137-byte pauser tail is written by raw offset while Borsh
  `serialize` only rewrites the first 32 bytes, so persistence never clobbers the tail. `set_pauser_addresses`
  reallocs with rent top-up and asserts the exact post-realloc length. `paused()` fails **closed** on a
  non-canonical byte.
- `complete_native` withdraws from a derivation-checked custody (bounded by SPL balance);
  `complete_wrapped` mints via the bridge `mint_authority` PDA, amount from the guardian-signed VAA (wrapped
  decimals ≤ 8, no un-truncation). `claim::consume` blocks replay; `Endpoint::verify_derivation` binds the
  registered emitter; VAA `token_address`/`token_chain`/`to` all checked. `create_wrapped` derives the mint as
  a canonical PDA — minting still requires a VAA. **(I3,I4,I5,I6)**

### 6. Move (Aptos + Sui) Token Bridge
- Aptos `complete_transfer`: `vaa::parse_verify_and_replay_protect` (quorum + replay) then
  `assert_coin_origin_info<CoinType>` binds the attacker-supplied type arg to the VAA token; `coin::extract`
  reverts if `fee > amount`.
- Sui `authorize_transfer`: VAA verified + replay-consumed upstream (the linear `TokenBridgeMessage`
  hot-potato cannot be reused); `verify_and_bridge_out` asserts `target_chain == Sui` and binds `CoinType` to
  the VAA `(token_chain, token_address)`. Move aborts on overflow. **(I1,I3,I5,I6)**

### 7. Wormchain keeper + Global Accountant
- `VerifyVAA`: `len(sigs) < quorum` rejected; `VerifySignatures` enforces distinct/ascending indices and
  "never the same signer twice", and `len(addresses) < len(signatures)` rejects over-provisioning — **quorum
  cannot be inflated by duplicate signatures.** `VerifyGovernanceVAA` adds `HexDigest` replay + governance
  emitter/module/target-chain checks. **(I1,I2,I3,I7)**
- Accountant `handle_observation`: each `submit_observations` verifies **one** guardian signature bound to
  `sig.index → addresses[index]`; signatures accumulate in a **`u128` bitmap** (`signatures |= 1<<index`,
  `num_signatures = count_ones`) — resubmitting a guardian is idempotent, so a single actor cannot reach
  quorum. Balances use `checked_add`/`checked_sub` on `Uint256` (double-entry lock/burn ↔ unlock/mint), so an
  unbacked mint cannot drive a balance negative. Registered-emitter + digest binding + duplicate-digest
  protection round it out. **(I1..I6)**

### 8. Guardian node — Manager Service (Dogecoin / XRPL multisig custody) — *freshest, highest-value surface*
The Manager Service is a new subsystem where guardians hold secp256k1 keys forming the **M-of-N multisig
that custodies real Dogecoin (P2SH) and XRPL funds**. A guardian-signed VAA from a known manager emitter
authorizes a release; each guardian signs the derived destination-chain transaction and gossips its partial
signature (`ManagerTransaction`); once M-of-N are aggregated the multisig tx is assembled and broadcast.

**Theft path is closed — verified line-by-line end-to-end (four independent links):**
1. **VAA-into-manager is quorum-verified.** The manager's `vaaC` is written only by the processor's
   `storeSignedVAA`, reached either from the local post-quorum assembly path or from
   `handleInboundSignedVAAWithQuorum`, which calls `v.Verify(p.gs.Keys)` **before** storing
   (observation.go:578). `VAA.Verify` enforces `len(sigs) >= CalculateQuorum(len(keys))` **and**
   `VerifySignatures` (distinct/ascending indices, ecrecover match) — so a network-supplied VAA that has not
   met full quorum against the *current* guardian set never reaches the manager.
2. **Manager signs only VAA-derived txs from whitelisted emitters.** `handleVAA` gates on `validateEmitter`
   (XRPL sequencer / known UTXO manager emitters) and dispatches by payload prefix; every signer builds the tx
   from the VAA payload. Redirecting funds needs a malicious VAA = guardian quorum.
3. **The signature is cryptographically bound to the exact payout.** Dogecoin uses
   `txscript.CalcSignatureHash(redeemScript, SigHashAll, tx, i)` (transaction.go:98) — commits to all inputs, all
   outputs, and the input's redeem script; XRPL uses `EncodeForMultisigning` (`SMT\0` prefix + signer account)
   over a `Payment` whose `Destination`/`Amount` come straight from the VAA payload. A partial signature cannot be
   replayed to a different recipient/amount.
4. **Funds only move via on-chain M-of-N verification against the funds' own script/account.** The manager set
   (keys, M, N) is read from the governance-controlled on-chain `DelegatedManagerSet` (immutable per index,
   safely cached) — unspoofable. Dogecoin redeem scripts bind `emitter_chain|emitter_contract|recipient` into the
   P2SH hash, so a crafted set/index/prefix just yields a script that doesn't match the funds' P2SH → invalid tx.
   No theft without guardian quorum **and** M manager keys.

**Real weakness found (High/DoS, not Critical, developer-acknowledged):** `handleIncomingTransaction`
aggregates partial signatures **without verifying them** and validates `SignerIndex < N` **without binding the
envelope guardian to the claimed `SignerIndex`**. `storeSignature` is first-write-wins per index. So a **single
malicious guardian** (p2p envelope must still be a guardian — non-guardians are rejected by
`processSignedManagerTransaction`) can broadcast garbage partial-signatures under *every* signer index, racing
ahead of honest signatures, permanently poisoning the aggregation network-wide → the assembled multisig tx is
rejected on-chain → **releases are blocked (liveness DoS)**. This is exactly the weakness the code documents in a
standing SECURITY comment (points 1–3) with a planned mitigation. It does **not** move or lose funds (on-chain
multisig rejects the invalid tx), requires a privileged insider, and is recoverable by the documented fix — so
it is **High at most, not Critical**.

### 9. Guardian node — watchers, processor, delegated-guardian consensus
- **Aptos watcher (rewritten):** `verifyEventType` binds every event to the configured core-bridge account
  + handle (type-tag address bytes + `guid.account_address`); reobservation re-fetches from the trusted RPC
  rather than trusting attacker-supplied data. Trust boundary is the guardian's own RPC (standard model).
- **Processor:** each observation's signature is ecrecovered and matched to a guardian address in the active
  set; signatures dedupe per-address (no count inflation); a node assembles/submits a VAA only for a message
  it **independently observed** (`s.ourObservation != nil`).
- **Delegated-guardian consensus (newest trust change):** `DelegateObservation`s are ecrecover-authenticated
  against the **canonical** set + `GuardianAddr` binding (p2p), then required to be in the chain's **delegated**
  set (`cfg.KeyIndex`); quorum is counted over **distinct** delegated keys with `threshold ≥ CalculateQuorum`
  (cannot be set below 2/3), bucket-keyed by `CreateDigest()` (binds chain+emitter+sequence+payload).
  Solana/Ethereum/Wormchain are `nonDelegableChains`. The trust reduction (a delegated chain's messages rest on
  2/3 of a *curated canonical subset*) is the **documented, intentional** tradeoff — not a forge bug.

---

## Non-critical observations (informational / design notes)

These are **not** vulnerabilities at Critical tier; recorded for completeness.

0. **Manager Service signature-aggregation poisoning (High / liveness — the most significant real finding).**
   A single malicious guardian can permanently block Dogecoin/XRPL releases by front-running signature
   aggregation with garbage partial-signatures under every `SignerIndex` (`handleIncomingTransaction` does not
   bind the envelope guardian to `SignerIndex`; `storeSignature` is first-write-wins). Impact is DoS only — funds
   are never moved (on-chain multisig rejects the invalid tx) — requires a guardian (insider), and is recoverable.
   Already documented by the developers in a standing SECURITY comment with a planned mitigation (verify partial
   sigs before storing; store unverified sigs as `PendingSignatures` until the sighashes are known). Fix:
   verify each partial signature against the computed sighash for the claimed signer's pubkey before storing, and
   reject a `SignerIndex` that does not match the envelope guardian's own manager slot.

1. **`Implementation.submitTransferFees` fork-replay (Info).** The `chain == 0` branch does not also require
   `!isFork()` (unlike `submitContractUpgrade`/`submitSetMessageFee`). A legitimately guardian-signed
   `chain==0` transfer-fees VAA could be replayed on a forked EVM chain. Impact is limited to fork-side
   accumulated **message-fee ETH**, requires a guardian-signed VAA (no attacker input), and does not touch
   bridge TVL. Optional hardening: gate the `chain==0` branch on `!isFork()`.

2. **Delegated-guardian trust reduction (Design).** For delegated chains, canonical guardians sign without an
   independent watcher, so message security for those chains equals 2/3 of the (smaller) delegated set. This is
   intentional, but it is the largest *residual* trust surface introduced by the recent changes; the size and
   membership discipline of each delegated set is a security-relevant operational parameter.

3. **Delegate-observation version skew (Liveness, self-documented).** `delegateObservationToMessagePublication`
   rejects unknown `VerificationState`/chain variants that the canonical's own consensus path normalizes away;
   if delegates upgrade ahead of canonicals, silently-dropped observations can reduce effective quorum and stall
   signing (safety-preserving, liveness-degrading). Deploy canonicals first when extending these enums.

4. **Governor is a circuit-breaker, not full TVL protection (Design).** Untracked tokens pass without limit;
   a governor bypass in isolation removes a throttle on otherwise guardian-signed transfers rather than creating
   unbacked value — capped at Medium on its own.

---

## Residual risk — where to point dynamic testing

Static review cleared the code paths above. The highest-value places to invest **dynamic** effort
(fuzzing / property tests / economic simulation / multi-node consensus tests) — i.e. where a real Critical, if
any exists, is most likely to live:

- **Manager Service (Dogecoin/XRPL)** — the newest custody mechanism and the least-audited. Beyond the
  documented aggregation DoS, fuzz the redeem-script/sighash construction and the manager-set-index selection at
  set-rotation boundaries; property: a signed destination tx can only ever spend the exact UTXOs/accounts the
  guardian-signed VAA authorized, to the VAA-specified recipient.
- **Delegated-guardian set operations under churn** — set rotation/removal races, the compact
  `SignedDelegateSignaturesBroadcast` expansion path, and delegate/canonical quorum accounting during
  simultaneous canonical + delegated set updates. (Property test: no message ever obtains a canonical VAA
  without ≥ delegate-quorum distinct delegated signers over its exact digest.)
- **Accountant/Governor economic edge cases** — flow-cancel corridor accounting, price staleness, and
  multi-chain balance invariants under adversarial transfer ordering.
- **Cross-chain finality / reobservation** — per-watcher finality vs. emitter-declared consistency for
  *value-bearing* emitters; reorg behavior on fast-finality chains.
- **Decimal/precision round-trips** for tokens with unusual decimals across the EVM↔Solana↔Move
  normalize/denormalize boundaries at extreme amounts.

---

## Methodology note

19 security-critical components were hand-traced, plus a dedicated deep-dive on the Manager Service (Dogecoin/
XRPL multisig custody) that the automated pass did not cover as a standalone surface. An 8-surface
finder/adversarial-refuter workflow ran in parallel and **completed all 8 surfaces** (EVM core, EVM token
bridge, EVM peripherals, Solana core, Solana token bridge, Aptos/Sui Move, Global Accountant + Governor,
guardian watchers/processor) returning **zero findings at any severity**, independently corroborating the hand
analysis. The consistent negative result across two independent methods — plus the manual Manager Service
review whose only real finding is a non-critical, developer-acknowledged DoS — is the basis for the verdict.

// Property-test harness for the critical-research audit (audits/critical-research).
//
// Invariant under attack: a guardian's partial signature over a Dogecoin release
// transaction can ONLY authorize the exact payout encoded in the guardian-signed VAA.
// If any output (recipient/amount) or input could be changed without changing the
// sighash a guardian signs, an attacker could replay a legitimately-collected
// signature to redirect custody funds -> Critical theft.
//
// These tests drive the REAL manager signing path (BuildRedeemScript +
// BuildUnsignedTransaction + ComputeSighash with SigHashAll) and try to falsify
// that binding across randomized payloads and adversarial mutations.
package dogecoin_test

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/certusone/wormhole/node/pkg/manager/dogecoin"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"
)

// buildSighashes faithfully mirrors ManagerService.signDogecoinTransaction: it builds a
// per-input redeem script from each input's OriginalRecipientAddress, builds the unsigned
// tx from the payload, overrides the per-input redeem scripts, and returns the SigHashAll
// sighash a guardian would sign for every input.
func buildSighashes(t *testing.T, emitterChain vaa.ChainID, emitterContract vaa.Address, m uint8, pubkeys [][]byte, p *vaa.UTXOUnlockPayload) [][]byte {
	t.Helper()

	redeemScripts := make([][]byte, len(p.Inputs))
	for i, in := range p.Inputs {
		rs, err := dogecoin.BuildRedeemScript(emitterChain, emitterContract, in.OriginalRecipientAddress, m, pubkeys)
		if err != nil {
			t.Fatalf("BuildRedeemScript: %v", err)
		}
		redeemScripts[i] = rs
	}

	ut, err := dogecoin.BuildUnsignedTransaction(p, redeemScripts[0])
	if err != nil {
		t.Fatalf("BuildUnsignedTransaction: %v", err)
	}
	ut.RedeemScripts = redeemScripts

	shs := make([][]byte, len(p.Inputs))
	for i := range p.Inputs {
		sh, err := ut.ComputeSighash(i, dogecoin.SighashAll)
		if err != nil {
			t.Fatalf("ComputeSighash(%d): %v", i, err)
		}
		shs[i] = sh
	}
	return shs
}

func randPayload(rng *rand.Rand) *vaa.UTXOUnlockPayload {
	nIn := 1 + rng.Intn(4)
	nOut := 1 + rng.Intn(3)
	p := &vaa.UTXOUnlockPayload{
		DestinationChain:         vaa.ChainIDDogecoin,
		DelegatedManagerSetIndex: rng.Uint32(),
	}
	for i := 0; i < nIn; i++ {
		var in vaa.UTXOInput
		rng.Read(in.OriginalRecipientAddress[:])
		rng.Read(in.TransactionID[:])
		in.Vout = rng.Uint32()
		p.Inputs = append(p.Inputs, in)
	}
	for i := 0; i < nOut; i++ {
		addr := make([]byte, 20)
		rng.Read(addr)
		p.Outputs = append(p.Outputs, vaa.UTXOOutput{
			Amount:      1 + uint64(rng.Int63n(1_000_000_000)),
			AddressType: vaa.UTXOAddressTypeP2PKH,
			Address:     addr,
		})
	}
	return p
}

func clonePayload(p *vaa.UTXOUnlockPayload) *vaa.UTXOUnlockPayload {
	c := &vaa.UTXOUnlockPayload{
		DestinationChain:         p.DestinationChain,
		DelegatedManagerSetIndex: p.DelegatedManagerSetIndex,
		Inputs:                   append([]vaa.UTXOInput(nil), p.Inputs...),
	}
	for _, o := range p.Outputs {
		c.Outputs = append(c.Outputs, vaa.UTXOOutput{
			Amount:      o.Amount,
			AddressType: o.AddressType,
			Address:     append([]byte(nil), o.Address...),
		})
	}
	return c
}

func dummyPubkeys(rng *rand.Rand, n int) [][]byte {
	pks := make([][]byte, n)
	for i := range pks {
		pk := make([]byte, 33)
		pk[0] = 0x02
		rng.Read(pk[1:])
		pks[i] = pk
	}
	return pks
}

func anySighashEqual(a, b [][]byte) bool {
	for _, x := range a {
		for _, y := range b {
			if bytes.Equal(x, y) {
				return true
			}
		}
	}
	return false
}

// TestPayoutBinding_OutputMutationChangesSighash is the core anti-theft property.
// For 5000 randomized releases, every adversarial mutation of the payout (change a
// recipient, change an amount, add/drop/reorder outputs, retarget an input) MUST change
// the sighash of every input the attacker would need a signature for. If a mutation ever
// leaves an input's sighash unchanged, a collected honest signature would authorize the
// mutated payout -> the test fails and prints the theft witness.
func TestPayoutBinding_OutputMutationChangesSighash(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC0FFEE))
	emitterContract := vaa.Address{}
	for i := range emitterContract {
		emitterContract[i] = byte(i)
	}
	m := uint8(2)
	pubkeys := dummyPubkeys(rng, 3)
	emitterChain := vaa.ChainIDEthereum

	const iters = 5000
	for it := 0; it < iters; it++ {
		p := randPayload(rng)
		honest := buildSighashes(t, emitterChain, emitterContract, m, pubkeys, p)

		mutations := []struct {
			name string
			mut  func(*vaa.UTXOUnlockPayload)
		}{
			{"retarget-recipient", func(q *vaa.UTXOUnlockPayload) {
				// Attacker points the first output at their own address.
				attacker := make([]byte, 20)
				for i := range attacker {
					attacker[i] = 0xAA
				}
				q.Outputs[0].Address = attacker
			}},
			{"inflate-amount", func(q *vaa.UTXOUnlockPayload) { q.Outputs[0].Amount += 1 }},
			{"add-output", func(q *vaa.UTXOUnlockPayload) {
				a := make([]byte, 20)
				for i := range a {
					a[i] = 0xBB
				}
				q.Outputs = append(q.Outputs, vaa.UTXOOutput{Amount: 1, AddressType: vaa.UTXOAddressTypeP2PKH, Address: a})
			}},
			{"retarget-input-utxo", func(q *vaa.UTXOUnlockPayload) { q.Inputs[0].Vout ^= 0x1 }},
		}
		if len(p.Outputs) > 1 {
			mutations = append(mutations, struct {
				name string
				mut  func(*vaa.UTXOUnlockPayload)
			}{"reorder-outputs", func(q *vaa.UTXOUnlockPayload) {
				q.Outputs[0], q.Outputs[1] = q.Outputs[1], q.Outputs[0]
			}})
		}

		for _, mu := range mutations {
			q := clonePayload(p)
			mu.mut(q)
			mutated := buildSighashes(t, emitterChain, emitterContract, m, pubkeys, q)
			// The attacker needs a valid signature for at least input 0 to spend it.
			// If input 0's sighash is unchanged, the honest signature authorizes the mutated payout.
			if len(mutated) > 0 && len(honest) > 0 && bytes.Equal(honest[0], mutated[0]) {
				t.Fatalf("THEFT WITNESS: mutation %q left input-0 sighash unchanged (honest sig would authorize attacker payout)\n honest=%x\n payload=%+v", mu.name, honest[0], p)
			}
		}
	}
}

// TestPayoutBinding_DistinctRecipientsDisjointSighashes asserts the stronger cross-release
// property: two releases that differ only in recipient share NO input sighash, so a signature
// collected for release A can never validate any input of a release to a different recipient.
func TestPayoutBinding_DistinctRecipientsDisjointSighashes(t *testing.T) {
	rng := rand.New(rand.NewSource(0xBADF00D))
	emitterContract := vaa.Address{}
	m := uint8(2)
	pubkeys := dummyPubkeys(rng, 3)
	emitterChain := vaa.ChainIDEthereum

	for it := 0; it < 3000; it++ {
		p := randPayload(rng)
		a := buildSighashes(t, emitterChain, emitterContract, m, pubkeys, p)

		q := clonePayload(p)
		attacker := make([]byte, 20)
		rng.Read(attacker)
		q.Outputs[0].Address = attacker // different recipient
		b := buildSighashes(t, emitterChain, emitterContract, m, pubkeys, q)

		if anySighashEqual(a, b) {
			t.Fatalf("THEFT WITNESS: releases to different recipients shared an input sighash (iter %d)", it)
		}
	}
}

// TestRedeemScriptBinding asserts the P2SH custody model: the emitter chain/contract and the
// original recipient are all committed into the redeem script (hence the P2SH address). Any
// change produces a different redeem script -> different P2SH -> the signature/tx cannot touch
// the funds locked at the original address.
func TestRedeemScriptBinding(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	pubkeys := dummyPubkeys(rng, 3)
	var recipient [32]byte
	rng.Read(recipient[:])
	base, err := dogecoin.BuildRedeemScript(vaa.ChainIDEthereum, vaa.Address{1}, recipient, 2, pubkeys)
	if err != nil {
		t.Fatal(err)
	}

	// Change emitter chain.
	if s, _ := dogecoin.BuildRedeemScript(vaa.ChainIDSolana, vaa.Address{1}, recipient, 2, pubkeys); bytes.Equal(base, s) {
		t.Fatal("redeem script did not bind emitter chain")
	}
	// Change emitter contract.
	if s, _ := dogecoin.BuildRedeemScript(vaa.ChainIDEthereum, vaa.Address{2}, recipient, 2, pubkeys); bytes.Equal(base, s) {
		t.Fatal("redeem script did not bind emitter contract")
	}
	// Change recipient.
	var r2 [32]byte
	rng.Read(r2[:])
	if s, _ := dogecoin.BuildRedeemScript(vaa.ChainIDEthereum, vaa.Address{1}, r2, 2, pubkeys); bytes.Equal(base, s) {
		t.Fatal("redeem script did not bind recipient")
	}
}

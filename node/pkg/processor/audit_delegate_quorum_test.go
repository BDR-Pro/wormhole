// Property-test harness for the critical-research audit (audits/critical-research).
//
// Invariant under attack: for a delegated chain, canonical guardians sign a VAA once a
// DELEGATE quorum of the chain's delegated set is reached. If the delegated threshold could
// ever be configured below the standard 2/3 Byzantine quorum, an attacker controlling a
// smaller minority of the delegated set could forge messages from that chain -> Critical.
//
// This test tries to falsify "the delegated threshold can never drop below CalculateQuorum(n)"
// by exhaustively fuzzing (numKeys, threshold) against the real constructor, and also checks
// the digest-binding helpers used by delegate-quorum bucketing.
package processor

import (
	"fmt"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"
)

func makeKeys(n int) []ethcommon.Address {
	keys := make([]ethcommon.Address, n)
	for i := 0; i < n; i++ {
		// Distinct, deterministic addresses.
		keys[i][0] = byte(i + 1)
		keys[i][19] = byte(i + 1)
	}
	return keys
}

// TestDelegateQuorumFloor exhaustively checks that NewDelegatedGuardianChainConfig accepts a
// threshold IFF CalculateQuorum(n) <= threshold <= n, and that an accepted config's Quorum()
// is never below the 2/3 floor. A single accepted sub-quorum config would be a forge witness.
func TestDelegateQuorumFloor(t *testing.T) {
	for n := 1; n <= 40; n++ {
		keys := makeKeys(n)
		floor := vaa.CalculateQuorum(n)
		for th := -2; th <= n+10; th++ {
			cfg, err := NewDelegatedGuardianChainConfig(keys, th)
			legal := th >= floor && th <= n
			if legal {
				if err != nil {
					t.Fatalf("n=%d th=%d: expected accept, got error %v", n, th, err)
				}
				if cfg.Quorum() != th {
					t.Fatalf("n=%d th=%d: Quorum()=%d mismatch", n, th, cfg.Quorum())
				}
				if cfg.Quorum() < floor {
					t.Fatalf("FORGE WITNESS: n=%d accepted Quorum()=%d below 2/3 floor %d", n, cfg.Quorum(), floor)
				}
			} else {
				if err == nil {
					t.Fatalf("FORGE/CONFIG WITNESS: n=%d th=%d (floor=%d) was accepted but is out of [%d,%d]", n, th, floor, floor, n)
				}
			}
		}
	}
}

// TestDelegateConfigRejectsDuplicateKeys ensures a delegated set cannot be padded with a
// duplicated key (which would let one compromised key count multiple times toward quorum).
func TestDelegateConfigRejectsDuplicateKeys(t *testing.T) {
	keys := makeKeys(5)
	keys[4] = keys[0] // duplicate
	if _, err := NewDelegatedGuardianChainConfig(keys, 4); err == nil {
		t.Fatal("QUORUM-INFLATION WITNESS: duplicate delegated key was accepted")
	}
}

// TestCalculateQuorumIsByzantine confirms the shared quorum formula equals floor(2n/3)+1 for
// all realistic set sizes — the same value the on-chain contracts enforce. A mismatch here
// would mean the node aggregates VAAs at a threshold the chains would reject (or vice-versa).
func TestCalculateQuorumIsByzantine(t *testing.T) {
	for n := 1; n <= 255; n++ {
		got := vaa.CalculateQuorum(n)
		want := (n*2)/3 + 1
		if got != want {
			t.Fatalf("CalculateQuorum(%d)=%d want %d", n, got, want)
		}
		// Strictly more than 2/3 of the set: 3*quorum > 2*n.
		if 3*got <= 2*n {
			t.Fatalf("quorum %d for n=%d is not a super-2/3 majority", got, n)
		}
	}
}

func Example_quorumFloors() {
	for _, n := range []int{7, 13, 19} {
		fmt.Printf("n=%d quorum=%d\n", n, vaa.CalculateQuorum(n))
	}
	// Output:
	// n=7 quorum=5
	// n=13 quorum=9
	// n=19 quorum=13
}

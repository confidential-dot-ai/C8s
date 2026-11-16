package cdsha

import (
	"encoding/hex"
	"slices"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

// What a replica admits before it joins a cluster: its own image, and the
// images an Admit decree names for the member id it minted at its start.

// admitDecree is the Admit decree the operator signs for r.
func (c *liveCluster) admitDecree(r *liveReplica, digests ...byte) cdsdecree.Decree {
	c.t.Helper()
	decree := c.fixture(r).decree(cdsdecree.Admit)
	decree.TargetMember = string(r.node.member)
	decree.CDSPins = testPins(c.t, digests...)
	return decree
}

// admittedImageSet are the image digests a replica admits a peer by, each once.
func admittedImageSet(n *Node) []string {
	var digests []string
	for _, image := range n.admits() {
		digests = append(digests, hex.EncodeToString(image.Digest))
	}
	slices.Sort(digests)
	return slices.Compact(digests)
}

// A replica that holds no cluster admits the images the Admit decree posted
// to it names beside its own, and its own alone once that decree expires.
func TestAnAdmitDecreeNamesWhatAnUnjoinedReplicaAdmitsBesideItsOwnImage(t *testing.T) {
	c := newLiveCluster(t)
	r := c.start()
	own := []string{testCDSImage}
	decree := c.admitDecree(r, testCDSDigest, rolledCDSDigest)
	decree.ExpiresAt = time.Now().Add(2 * time.Second)

	c.posted(r, c.signDecree(decree))

	rolled := []string{testCDSImage, rolledCDSImage}
	slices.Sort(rolled)
	eventually(t, 5*time.Second, "the replica admitting the decreed images", func() bool {
		return slices.Equal(admittedImageSet(r.node), rolled)
	})
	eventually(t, 10*time.Second, "the replica admitting its own image alone once the Admit expires", func() bool {
		return slices.Equal(admittedImageSet(r.node), own)
	})
}

// An Admit decree naming another member is not even taken, and one past its
// expiry leaves a replica admitting its own image alone.
func TestAnAdmitDecreeForAnotherMemberOrPastItsExpiryAdmitsNothing(t *testing.T) {
	c := newLiveCluster(t)
	r := c.start()
	replayed := c.admitDecree(r, testCDSDigest, rolledCDSDigest)
	replayed.TargetMember = testMember
	expired := c.admitDecree(r, testCDSDigest, rolledCDSDigest)
	expired.ExpiresAt = time.Now().Add(-time.Minute)

	if _, err := r.node.TakeDecree(c.signDecree(replayed)); err == nil {
		t.Fatal("a replica took an Admit decree naming another member")
	}
	c.posted(r, c.signDecree(expired))

	r.node.admitAsDecreed()
	if admitted := admittedImageSet(r.node); !slices.Equal(admitted, []string{testCDSImage}) {
		t.Fatalf("the replica admits %v", admitted)
	}
}

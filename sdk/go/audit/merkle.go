package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Merkle domain-separation prefixes prevent a leaf hash from ever colliding
// with an interior node hash (the classic second-preimage defense).
const (
	merkleLeafPrefix = 0x00
	merkleNodePrefix = 0x01
)

// MerkleSibling is one step of an inclusion proof: the sibling digest and
// whether it sits to the RIGHT of the running hash (so the pair combines as
// H(node || sibling)); Right=false places the sibling on the LEFT.
type MerkleSibling struct {
	Hash  string `json:"hash"`
	Right bool   `json:"right"`
}

// MerkleWitness is an inclusion proof for one leaf: the sibling path from the
// leaf up to the root, in leaf-to-root order.
type MerkleWitness struct {
	LeafIndex int             `json:"leaf_index"`
	Siblings  []MerkleSibling `json:"siblings"`
}

// leafDigest hashes one leaf value (an event_hash string) under the leaf domain.
func leafDigest(value string) string {
	sum := sha256.Sum256(append([]byte{merkleLeafPrefix}, []byte(value)...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// nodeDigest hashes two child digests under the interior-node domain.
func nodeDigest(left, right string) string {
	h := sha256.New()
	h.Write([]byte{merkleNodePrefix})
	h.Write([]byte(left))
	h.Write([]byte(right))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// MerkleRoot computes the batch Merkle root over the ordered event-hash leaves.
// An odd node at any level is promoted unchanged to the next level (a
// deterministic, witness-friendly scheme). It errors on an empty batch: a WORM
// batch always covers at least one event.
func MerkleRoot(eventHashes []string) (string, error) {
	if len(eventHashes) == 0 {
		return "", errors.New("merkle root over an empty batch")
	}
	level := make([]string, len(eventHashes))
	for i, value := range eventHashes {
		level[i] = leafDigest(value)
	}
	for len(level) > 1 {
		var next []string
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i]) // promote the odd tail unchanged
				break
			}
			next = append(next, nodeDigest(level[i], level[i+1]))
		}
		level = next
	}
	return level[0], nil
}

// MerkleProof builds the inclusion witness for the leaf at index within the
// ordered event-hash batch.
func MerkleProof(eventHashes []string, index int) (MerkleWitness, error) {
	if index < 0 || index >= len(eventHashes) {
		return MerkleWitness{}, errors.New("merkle proof index out of range")
	}
	level := make([]string, len(eventHashes))
	for i, value := range eventHashes {
		level[i] = leafDigest(value)
	}
	witness := MerkleWitness{LeafIndex: index}
	pos := index
	for len(level) > 1 {
		var next []string
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				break
			}
			parent := nodeDigest(level[i], level[i+1])
			next = append(next, parent)
		}
		if pos%2 == 0 {
			if pos+1 < len(level) {
				witness.Siblings = append(witness.Siblings, MerkleSibling{Hash: level[pos+1], Right: true})
			}
			// else: promoted, no sibling recorded this level.
		} else {
			witness.Siblings = append(witness.Siblings, MerkleSibling{Hash: level[pos-1], Right: false})
		}
		pos /= 2
		level = next
	}
	return witness, nil
}

// VerifyMerkleProof recomputes the root from a leaf value and its witness and
// reports whether it matches root.
func VerifyMerkleProof(leafValue, root string, witness MerkleWitness) bool {
	running := leafDigest(leafValue)
	for _, sibling := range witness.Siblings {
		if sibling.Right {
			running = nodeDigest(running, sibling.Hash)
		} else {
			running = nodeDigest(sibling.Hash, running)
		}
	}
	return running == root
}

package merkle

import (
	"encoding/binary"
	protocol "file_transfer/Protocol"
	utils "file_transfer/Utils"
)

func GenerateLeaf(chunk *protocol.Chunk) []byte {

	index := make([]byte, 4)
	binary.BigEndian.PutUint32(index, chunk.Index)

	return utils.Keccak(
		chunk.FileID,
		index,
		chunk.Nonce,
		chunk.Ciphertext,
		chunk.HResp,
	)
}

// this func builds a merkle tree based on the given leaves, a full merkle tree of [][][]byte type, and in case u want just the root, just see the Root_of_tree function, and extract the root and return that, but as of now this function returns the whole tree
func BuildTree(leaves [][]byte) [][][]byte { // leaves is the list of hashes/leaves, that will create a merkle root

	if len(leaves) == 0 {
		return nil
	}

	tree := [][][]byte{} // THIS IS A VERY IMP STATEMENT, [][][] ISKO SAMJH !!!!!
	// this looks smth like this :
	//	[
	//     [L0 L1 L2 L3],
	//     [P0 P1],
	//     [Root]
	// 	]
	// and ofc each one of this L1, L2 .... are hashes so they themselves are []byte
	// Also notice this is an ulta tree

	current := leaves

	// append the leaf layer to the tree
	tree = append(tree, current)

	// this loop basically creates layers until the layer has only 1 element which is gonna be the root
	for len(current) > 1 {
		// next holds a layer
		var next [][]byte

		for i := 0; i < len(current); i += 2 { // notice i+=2

			left := current[i]

			var right []byte

			if i+1 < len(current) {
				right = current[i+1]
			} else {
				right = current[i] // if the no is odd it will repeat the last element
			}

			parent := utils.Keccak(left, right) // join the right and left

			next = append(next, parent)
		}

		current = next

		tree = append(tree, current)

	}

	return tree
}

func Root_of_tree(tree [][][]byte) []byte {

	if len(tree) == 0 {
		return nil
	}

	lastLevel := tree[len(tree)-1]

	return lastLevel[0]
}

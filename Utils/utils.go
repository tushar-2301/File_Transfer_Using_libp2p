package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	protocol "file_transfer/Protocol"
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"
)

func Keccak(data ...[]byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	for _, d := range data {
		hasher.Write(d)
	}
	return hasher.Sum(nil)
}

func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, protocol.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// H_resp = Keccak(Key || Plaintext)
func ComputeResponseCommitment(chunk *protocol.Chunk) []byte {
	return Keccak(chunk.Key, chunk.Plaintext)
}

// chunk.Key (must already be set) and chunk.Plaintext.
func EncryptChunk(chunk *protocol.Chunk) error {
	NonceSize := protocol.NonceSize

	// this is just a block
	block, err := aes.NewCipher(chunk.Key)
	if err != nil {
		return err
	}

	// AES is fundamentally a block cipher. It only knows how to encrypt 16 bytes at a time.
	// AES requires exactly 16-byte blocks.

	// here its ctr/gcm
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// create a nonce and fill it randomly
	nonce := make([]byte, NonceSize)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return err
	}

	chunk.Nonce = nonce

	// finally create the ciphertxt
	ciphertext := gcm.Seal(nil, nonce, chunk.Plaintext, nil)

	chunk.Ciphertext = ciphertext

	// Seal(dst, nonce, plaintext, aad)
	// dst : destination, basically the create ciphertext woudl be appended to dst if given
	// aad : Additional Authenticated Data : AAD is authenticated but not encrypted. You may want these visible, eg u cant encrypt the header itself
	return nil
}

// DecryptAndCheck decrypts chunk.Ciphertext using chunk.Key/chunk.Nonce (AES-GCM),
// then verifies the result against the earlier commitment chunk.HResp
// (H_resp = Keccak(Key, Plaintext)) before handing back the plaintext.
//
// This is the second half of the commit-reveal check: the sender committed
// to HResp when it sent the chunk response, before revealing the key. If the
// key/plaintext now being revealed doesn't match that commitment, the sender
// equivocated and the chunk must be rejected — regardless of whether GCM
// authentication itself succeeded.
func DecryptAndCheck(chunk *protocol.Chunk) ([]byte, error) {

	block, err := aes.NewCipher(chunk.Key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, chunk.Nonce, chunk.Ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// Fill in Plaintext so ComputeResponseCommitment can use it — it's the
	// same field the sender populated when it originally built HResp.
	chunk.Plaintext = plaintext

	gotCommitment := ComputeResponseCommitment(chunk)
	if !bytesEqual(gotCommitment, chunk.HResp) {
		return nil, fmt.Errorf(
			"H_resp mismatch on chunk %d: sender revealed a key/plaintext that doesn't match its earlier commitment (got %x, want %x)",
			chunk.Index, gotCommitment, chunk.HResp,
		)
	}

	return plaintext, nil
}

// bytesEqual is a small constant-time-agnostic equality check; HResp isn't a
// secret being compared against a secret (it's already public on the wire),
// so a plain byte comparison is fine here — no need for subtle.ConstantTimeCompare.
func bytesEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}

// these encrypt and decrypt are claude func
// EncryptChunk fills chunk.Nonce and chunk.Ciphertext via AES-256-GCM,
// using chunk.Key (must already be set) and chunk.Plaintext.
// func EncryptChunk(chunk *protocol.Chunk) error {
// 	block, err := aes.NewCipher(chunk.Key)
// 	if err != nil {
// 		return err
// 	}
// 	gcm, err := cipher.NewGCM(block)
// 	if err != nil {
// 		return err
// 	}

// 	nonce := make([]byte, protocol.NonceSize)
// 	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
// 		return err
// 	}

// 	chunk.Nonce = nonce
// 	chunk.Ciphertext = gcm.Seal(nil, nonce, chunk.Plaintext, nil)
// 	return nil
// }

// // DecryptChunk uses chunk.Key + chunk.Nonce to recover chunk.Plaintext
// // from chunk.Ciphertext. Fixes the undefined nonce/ciphertext bug.
// func DecryptChunk(chunk *protocol.Chunk) ([]byte, error) {
// 	block, err := aes.NewCipher(chunk.Key)
// 	if err != nil {
// 		return nil, err
// 	}
// 	gcm, err := cipher.NewGCM(block)
// 	if err != nil {
// 		return nil, err
// 	}

// 	plaintext, err := gcm.Open(nil, chunk.Nonce, chunk.Ciphertext, nil)
// 	if err != nil {
// 		return nil, err
// 	}

// 	chunk.Plaintext = plaintext
// 	return plaintext, nil
// }

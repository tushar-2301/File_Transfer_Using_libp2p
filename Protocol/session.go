package protocol

import (
	"fmt"
	"log"
	"os"
	"sync"
)

type Role uint8

const (
	RoleSender Role = iota
	RoleReceiver
)

type Session struct {
	mu sync.Mutex

	state TransferState
	Role  Role
	Conn  Stream

	FileID       []byte
	FileName     string
	FileSize     uint64
	ChunkSize    uint32
	CurrentChunk uint32
	TotalChunks  uint32

	// File is the local handle: opened for read on the sender,
	// created for write on the receiver.
	File *os.File

	// PendingChunk holds the chunk currently "in flight" through the
	// request -> response -> lottery ticket -> key reveal round trip.
	// Sender: full chunk (plaintext, key, ciphertext) built at SendChunkResponse,
	// key is not put on the wire until SendKeyReveal.
	// Receiver: chunk received at WaitingChunkResponse (ciphertext, no key
	// yet), key filled in at WaitingKeyReveal, decrypted/verified at VerifyChunk.
	PendingChunk *Chunk

	// Leaves accumulates merkle leaves as chunks are confirmed, on both sides.
	Leaves [][]byte
}

func NewSession(conn Stream, role Role) *Session {
	return &Session{
		state:     StateIdle,
		Conn:      conn,
		Role:      role,
		ChunkSize: ChunkSize, // protocol.ChunkSize default, override after header exchange if needed
	}
}

func (s *Session) GetState() TransferState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *Session) Transition(next TransferState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !isAllowed(s.state, next) {
		return fmt.Errorf("illegal transition %s -> %s", s.state, next)
	}

	log.Printf(
		"[Chunk %d/%d] %s -> %s",
		s.CurrentChunk+1,
		s.TotalChunks,
		s.state,
		next,
	)
	s.state = next
	return nil
}

func isAllowed(current, next TransferState) bool {
	for _, st := range validTransitions[current] {
		if st == next {
			return true
		}
	}
	return false
}

func (s *Session) AdvanceChunk() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CurrentChunk++
}

// IsLastChunk must be called BEFORE AdvanceChunk for the current chunk.
func (s *Session) IsLastChunk() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.TotalChunks > 0 && s.CurrentChunk == s.TotalChunks-1
}

// Fail is the one place state is set without going through the transition
// table on purpose — Error must be reachable from anywhere.
func (s *Session) Fail(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	log.Printf("[FSM] %s -> Error: %v", s.state, err)
	s.state = StateError
	return err
}

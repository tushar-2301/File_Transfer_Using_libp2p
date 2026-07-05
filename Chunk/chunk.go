package chunk

import (
	"encoding/binary"
	protocol "file_transfer/Protocol"
	utils "file_transfer/Utils"
	"fmt"
	"io"
	"os"
)

const (
	msgHeader        byte = 0x01
	msgChunkRequest  byte = 0x02
	msgChunkResponse byte = 0x03
	msgLotteryTicket byte = 0x04
	msgKeyReveal     byte = 0x05
	msgMerkleRoot    byte = 0x06
	msgFinalAck      byte = 0x07
)

func readSentinel(conn protocol.Stream, want byte, what string) error {
	b := make([]byte, 1)
	if _, err := io.ReadFull(conn, b); err != nil {
		return fmt.Errorf("reading %s sentinel: %w", what, err)
	}
	if b[0] != want {
		return fmt.Errorf("expected %s (0x%02x), got 0x%02x", what, want, b[0])
	}
	return nil
}

// OLD SendHeader, everything same, except that this not only sends the header but also receives, the ack of the header
// func SendHeader(conn net.Conn, header protocol.MetaData, received []byte) error {
// 	headerBuffer := []byte{1} // buf := []byte{msgHeader}
// 	temp := make([]byte, 4)

// 	binary.BigEndian.PutUint32(temp, header.Reps)
// 	headerBuffer = append(headerBuffer, temp...)

// 	headerBuffer = append(headerBuffer, header.FileID...) // fixed HashSize bytes

// 	binary.BigEndian.PutUint32(temp, uint32(len(header.Name)))
// 	headerBuffer = append(headerBuffer, temp...)
// 	headerBuffer = append(headerBuffer, []byte(header.Name)...)

// 	binary.BigEndian.PutUint32(temp, header.FileSize)
// 	headerBuffer = append(headerBuffer, temp...)

// 	if _, err := conn.Write(headerBuffer); err != nil {
// 		return fmt.Errorf("couldn't write header: %w", err)
// 	}
// 	fmt.Println("Successfully sent the header of SendFile")

// 	if _, err := conn.Read(received); err != nil {
// 		return fmt.Errorf("couldn't read header ack: %w", err)
// 	}
// 	fmt.Println("Received the ack of header reached:", string(received))
// 	return nil
// }

// ---- Header ----

func SendHeader(conn protocol.Stream, header protocol.MetaData) error {
	buf := []byte{msgHeader}
	temp := make([]byte, 4)

	binary.BigEndian.PutUint32(temp, header.Reps)
	buf = append(buf, temp...)
	buf = append(buf, header.FileID...) // fixed HashSize bytes

	binary.BigEndian.PutUint32(temp, uint32(len(header.Name)))
	buf = append(buf, temp...)
	buf = append(buf, []byte(header.Name)...)

	binary.BigEndian.PutUint32(temp, header.FileSize)
	buf = append(buf, temp...)

	_, err := conn.Write(buf)
	return err
}

func ReadHeader(conn protocol.Stream) (protocol.MetaData, error) {
	var h protocol.MetaData
	if err := readSentinel(conn, msgHeader, "header"); err != nil {
		return h, err
	}

	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return h, fmt.Errorf("reading reps: %w", err)
	}
	h.Reps = binary.BigEndian.Uint32(buf)

	h.FileID = make([]byte, protocol.HashSize)
	if _, err := io.ReadFull(conn, h.FileID); err != nil {
		return h, fmt.Errorf("reading fileID: %w", err)
	}

	if _, err := io.ReadFull(conn, buf); err != nil {
		return h, fmt.Errorf("reading name length: %w", err)
	}
	nameBuf := make([]byte, binary.BigEndian.Uint32(buf))
	if _, err := io.ReadFull(conn, nameBuf); err != nil {
		return h, fmt.Errorf("reading name: %w", err)
	}
	h.Name = string(nameBuf)

	if _, err := io.ReadFull(conn, buf); err != nil {
		return h, fmt.Errorf("reading filesize: %w", err)
	}
	h.FileSize = binary.BigEndian.Uint32(buf)

	return h, nil
}

// ---- Chunk request (receiver -> sender) ----

func SendChunkRequest(conn protocol.Stream, index uint32) error {
	buf := []byte{msgChunkRequest}
	temp := make([]byte, 4)
	binary.BigEndian.PutUint32(temp, index)
	buf = append(buf, temp...)
	_, err := conn.Write(buf)
	return err
}

func ReadChunkRequest(conn protocol.Stream) (uint32, error) {
	if err := readSentinel(conn, msgChunkRequest, "chunk request"); err != nil {
		return 0, err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(buf), nil
}

// ---- Chunk response (sender -> receiver): ciphertext + commitment, NO KEY ----

// +------------+-------------+------------------+-------------+-----------+---------+
// | Sentinel   | Chunk Index | Ciphertext Length| Ciphertext  | Nonce     | HResp   |
// | 1 byte     | 4 bytes     | 4 bytes          | Variable    | 12 bytes  | 32 bytes|
// +------------+-------------+------------------+-------------+-----------+---------+

// this just takes an alr made chunk obj and just puts it on the wire
func SendChunkResponse(conn protocol.Stream, c *protocol.Chunk) error {
	buf := []byte{msgChunkResponse}
	temp := make([]byte, 4)

	// chunk index
	binary.BigEndian.PutUint32(temp, c.Index)
	buf = append(buf, temp...)

	// cipher text
	binary.BigEndian.PutUint32(temp, uint32(len(c.Ciphertext)))
	buf = append(buf, temp...)
	buf = append(buf, c.Ciphertext...)

	buf = append(buf, c.Nonce...) // fixed NonceSize
	buf = append(buf, c.HResp...) // fixed HashSize

	_, err := conn.Write(buf)
	return err
}

func ReadChunkResponse(conn protocol.Stream, fileID []byte) (*protocol.Chunk, error) {
	if err := readSentinel(conn, msgChunkResponse, "chunk response"); err != nil {
		return nil, err
	}

	buf := make([]byte, 4)

	// read chunk index
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	index := binary.BigEndian.Uint32(buf)

	// read the ciphetext len first and then create a buffer for cipher text of that len, and then read the cipher text
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	ciphertext := make([]byte, binary.BigEndian.Uint32(buf))
	if _, err := io.ReadFull(conn, ciphertext); err != nil {
		return nil, err
	}

	// read nonce
	nonce := make([]byte, protocol.NonceSize)
	if _, err := io.ReadFull(conn, nonce); err != nil {
		return nil, err
	}
	// read hresp
	hresp := make([]byte, protocol.HashSize)
	if _, err := io.ReadFull(conn, hresp); err != nil {
		return nil, err
	}

	return &protocol.Chunk{
		FileID: fileID, Index: index, Length: uint32(len(ciphertext)),
		Ciphertext: ciphertext, Nonce: nonce, HResp: hresp,
	}, nil
}

// ISME GADBAD HAIIIIIIIIIIIIIIIIIIIIIIIII
// ---- Lottery ticket (receiver -> sender): receipt for the response just received ----

func SendLotteryTicket(conn protocol.Stream, index uint32) error {
	buf := []byte{msgLotteryTicket}
	temp := make([]byte, 4)
	binary.BigEndian.PutUint32(temp, index)
	buf = append(buf, temp...)
	_, err := conn.Write(buf)
	return err
}

func ReadLotteryTicket(conn protocol.Stream) (uint32, error) {
	if err := readSentinel(conn, msgLotteryTicket, "lottery ticket"); err != nil {
		return 0, err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(buf), nil
}

// ---- Key reveal (sender -> receiver) ----

func SendKeyReveal(conn protocol.Stream, index uint32, key []byte) error {
	buf := []byte{msgKeyReveal}
	temp := make([]byte, 4)

	// sending the index of the chunk, whos key is being sent
	binary.BigEndian.PutUint32(temp, index)
	buf = append(buf, temp...)
	// sending the key of that chunk
	buf = append(buf, key...)
	_, err := conn.Write(buf)
	return err
}

func ReadKeyReveal(conn protocol.Stream) (uint32, []byte, error) {
	if err := readSentinel(conn, msgKeyReveal, "key reveal"); err != nil {
		return 0, nil, err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, nil, err
	}
	index := binary.BigEndian.Uint32(buf)

	key := make([]byte, protocol.KeySize)
	if _, err := io.ReadFull(conn, key); err != nil {
		return 0, nil, err
	}
	return index, key, nil
}

// ---- Merkle root + final ack ----

func SendRoot(conn protocol.Stream, root []byte) error {
	_, err := conn.Write(append([]byte{msgMerkleRoot}, root...))
	return err
}

func ReadRoot(conn protocol.Stream) ([]byte, error) {
	if err := readSentinel(conn, msgMerkleRoot, "merkle root"); err != nil {
		return nil, err
	}
	root := make([]byte, protocol.HashSize)
	if _, err := io.ReadFull(conn, root); err != nil {
		return nil, err
	}
	return root, nil
}

func SendFinalAck(conn protocol.Stream) error {
	_, err := conn.Write([]byte{msgFinalAck})
	return err
}

func ReadFinalAck(conn protocol.Stream) error {
	return readSentinel(conn, msgFinalAck, "final ack")
}

// ---- helpers used by the sender steps ----

// ReadChunkPlaintext reads chunk `index` from disk given the session's chunk size.
func ReadChunkPlaintext(file *os.File, index uint32, chunkSize uint32) ([]byte, error) {
	buf := make([]byte, chunkSize)
	n, err := file.ReadAt(buf, int64(chunkSize)*int64(index))
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}

// BuildAndEncryptChunk creates a fresh Chunk with a fresh key, encrypted, with
// HResp and Leaf computed. Key is NOT sent by SendChunkResponse — only later
// by SendKeyReveal.
func BuildAndEncryptChunk(fileID []byte, index uint32, plaintext []byte) (*protocol.Chunk, error) {
	c := protocol.NewChunk(fileID, index, plaintext)

	key, err := utils.GenerateRandomKey()
	if err != nil {
		return nil, fmt.Errorf("generating key for chunk %d: %w", index, err)
	}
	c.Key = key

	if err := utils.EncryptChunk(c); err != nil {
		return nil, fmt.Errorf("encrypting chunk %d: %w", index, err)
	}
	c.HResp = utils.ComputeResponseCommitment(c)

	return c, nil
}

// func SendChunksandReturnLeaves(file *os.File, conn net.Conn, header protocol.MetaData) ([][]byte, error) {

// 	dataBuffer := make([]byte, protocol.ChunkSize)
// 	var leaves [][]byte

// 	for i := 0; i < int(header.Reps); i++ {

// 		n, err := file.ReadAt(dataBuffer, int64(protocol.ChunkSize*i))
// 		if err != nil && err != io.EOF {
// 			log.Fatal("Error reading the file at a diff location:", err)
// 		}

// 		plaintext := make([]byte, n)
// 		copy(plaintext, dataBuffer[:n])

// 		newChunk := protocol.NewChunk(header.FileID, uint32(i), plaintext)

// 		key, err := utils.GenerateRandomKey() // every chunk gets its own key
// 		if err != nil {
// 			return nil, fmt.Errorf("couldn't generate key for chunk %d: %w", i, err)
// 		}
// 		newChunk.Key = key

// 		if err := utils.EncryptChunk(newChunk); err != nil {
// 			return nil, fmt.Errorf("couldn't encrypt chunk %d: %w", i, err)
// 		}

// 		newChunk.HResp = utils.ComputeResponseCommitment(newChunk)
// 		newChunk.Leaf = merkle.GenerateLeaf(newChunk)
// 		leaves = append(leaves, newChunk.Leaf)

// 		if err := sendChunkOnWire(conn, newChunk); err != nil {
// 			return nil, fmt.Errorf("couldn't send chunk %d: %w", i, err)
// 		}

// 		// leaf := merkle.GenerateLeaf(fileID, uint32(i), dataBuffer)
// 		// leaves = append(leaves, leaf)

// 		// // Chunk Index
// 		// binary.BigEndian.PutUint32(temp, uint32(i))
// 		// segmentBuffer = append(segmentBuffer, temp...)

// 		// // Chunk Size
// 		// binary.BigEndian.PutUint32(temp, uint32(n))
// 		// segmentBuffer = append(segmentBuffer, temp...)

// 		// segmentBuffer = append(segmentBuffer, dataBuffer[:n]...)

// 		// _, err = conn.Write(segmentBuffer)
// 		// if err != nil {
// 		// 	log.Fatal(err)
// 		// }

// 		// segmentBuffer = []byte{0}
// 	}

// 	return leaves, nil
// }

// // Wire format: sentinel(1)=0 | index(4) | ctLen(4) | ciphertext | key(32) | nonce(12) | hresp(32)
// func sendChunkOnWire(conn net.Conn, c *protocol.Chunk) error {
// 	buf := []byte{0}
// 	temp := make([]byte, 4)

// 	binary.BigEndian.PutUint32(temp, c.Index)
// 	buf = append(buf, temp...)

// 	binary.BigEndian.PutUint32(temp, uint32(len(c.Ciphertext)))
// 	buf = append(buf, temp...)
// 	buf = append(buf, c.Ciphertext...)

// 	buf = append(buf, c.Key...)
// 	buf = append(buf, c.Nonce...)
// 	buf = append(buf, c.HResp...)

// 	_, err := conn.Write(buf)
// 	return err
// }

// // SendRoot ships the Merkle root computed from all chunks so the receiver
// // can independently verify integrity of what it decrypted.
// func SendRoot(conn net.Conn, root []byte) error {
// 	_, err := conn.Write(append([]byte{2}, root...))
// 	return err
// }

// func WaitForFinalAck(conn net.Conn, received []byte) error {
// 	if _, err := conn.Read(received); err != nil {
// 		return fmt.Errorf("couldn't read final ack: %w", err)
// 	}
// 	fmt.Println("Received the final ack:", string(received))
// 	return nil
// }

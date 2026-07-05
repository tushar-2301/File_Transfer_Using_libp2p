package controllers

import (
	"bytes"
	"encoding/binary"
	chunk "file_transfer/Chunk"
	merkle "file_transfer/Merkle"
	protocol "file_transfer/Protocol"
	utils "file_transfer/Utils"
	"fmt"
	"log"
	"os"
	"time"
)

func PrepareMetadata(file *os.File) protocol.MetaData {

	fileInfo, err := file.Stat()
	filesize := fileInfo.Size()

	if err != nil {
		log.Fatal("Failed loading the fileInfo", err)
	}

	header := protocol.MetaData{
		Name:     fileInfo.Name(),
		FileSize: uint32(filesize),
		Reps:     uint32((filesize + protocol.ChunkSize - 1) / protocol.ChunkSize),
	}

	return header
}

func generateFileID(file *os.File) ([]byte, error) {
	info, err := file.Stat()

	if err != nil {
		log.Fatal("Error reading stats of the file", err)
	}

	filename := info.Name()
	filesize := info.Size()
	timestamp := time.Now().Unix()

	sizeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(sizeBytes, uint64(filesize))

	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timestamp))

	fileID := utils.Keccak([]byte(filename), sizeBytes, timeBytes)

	return fileID, nil
}

var senderSteps = protocol.StepTable{
	protocol.StateIdle:                 stepSenderIdle,
	protocol.StateSendHeader:           stepSenderSendHeader,
	protocol.StateWaitingChunkRequest:  stepSenderWaitChunkRequest,
	protocol.StateSendChunkResponse:    stepSenderSendChunkResponse,
	protocol.StateWaitingLotteryTicket: stepSenderWaitLotteryTicket,
	protocol.StateSendKeyReveal:        stepSenderSendKeyReveal,
	protocol.StateVerifyMerkle:         stepSenderVerifyMerkle,
}

// this function has been reduced to just open file and generate its fileID, prepare Metadata, and create a new Session
func SendFile(path string, conn protocol.Stream) error {

	file, err := os.OpenFile(path, os.O_RDONLY, 0775)
	if err != nil {
		log.Fatal("Error reading the file:", err)
	}
	defer file.Close()

	fileID, err := generateFileID(file)
	if err != nil {
		return fmt.Errorf("couldn't generate file ID: %w", err)
	}

	header := PrepareMetadata(file)
	header.FileID = fileID

	s := protocol.NewSession(conn, protocol.RoleSender)
	s.File = file
	s.FileID = fileID
	s.FileName = header.Name
	s.FileSize = uint64(header.FileSize)
	s.TotalChunks = header.Reps

	return protocol.Run(s, senderSteps)
}

func stepSenderIdle(s *protocol.Session) (protocol.TransferState, error) {
	return protocol.StateSendHeader, nil
}

func stepSenderSendHeader(s *protocol.Session) (protocol.TransferState, error) {
	header := protocol.MetaData{
		Name:     s.FileName,
		FileSize: uint32(s.FileSize),
		Reps:     s.TotalChunks,
		FileID:   s.FileID,
	}
	if err := chunk.SendHeader(s.Conn, header); err != nil {
		return 0, fmt.Errorf("sending header: %w", err)
	}
	if s.TotalChunks == 0 {
		return protocol.StateFinished, nil // nothing to send, nothing to verify
	}
	return protocol.StateWaitingChunkRequest, nil
}

func stepSenderWaitChunkRequest(s *protocol.Session) (protocol.TransferState, error) {
	idx, err := chunk.ReadChunkRequest(s.Conn)
	if err != nil {
		return 0, fmt.Errorf("reading chunk request: %w", err)
	}
	if idx != s.CurrentChunk {
		return 0, fmt.Errorf("out-of-order chunk request: want %d, got %d", s.CurrentChunk, idx)
	}
	return protocol.StateSendChunkResponse, nil
}

func stepSenderSendChunkResponse(s *protocol.Session) (protocol.TransferState, error) {
	plaintext, err := chunk.ReadChunkPlaintext(s.File, s.CurrentChunk, s.ChunkSize)
	if err != nil {
		return 0, fmt.Errorf("reading chunk %d from disk: %w", s.CurrentChunk, err)
	}

	c, err := chunk.BuildAndEncryptChunk(s.FileID, s.CurrentChunk, plaintext)
	if err != nil {
		return 0, err
	}

	if err := chunk.SendChunkResponse(s.Conn, c); err != nil {
		return 0, fmt.Errorf("sending chunk response %d: %w", s.CurrentChunk, err)
	}

	s.PendingChunk = c // key stays here until SendKeyReveal
	return protocol.StateWaitingLotteryTicket, nil
}

func stepSenderWaitLotteryTicket(s *protocol.Session) (protocol.TransferState, error) {
	idx, err := chunk.ReadLotteryTicket(s.Conn)
	if err != nil {
		return 0, fmt.Errorf("reading lottery ticket: %w", err)
	}
	if idx != s.CurrentChunk {
		return 0, fmt.Errorf("lottery ticket for wrong chunk: want %d, got %d", s.CurrentChunk, idx)
	}
	return protocol.StateSendKeyReveal, nil
}

func stepSenderSendKeyReveal(s *protocol.Session) (protocol.TransferState, error) {
	if err := chunk.SendKeyReveal(s.Conn, s.CurrentChunk, s.PendingChunk.Key); err != nil {
		return 0, fmt.Errorf("sending key reveal %d: %w", s.CurrentChunk, err)
	}

	s.PendingChunk.Leaf = merkle.GenerateLeaf(s.PendingChunk)
	s.Leaves = append(s.Leaves, s.PendingChunk.Leaf)

	last := s.IsLastChunk()

	s.PendingChunk = nil

	if last {
		return protocol.StateVerifyMerkle, nil
	}

	s.AdvanceChunk()

	return protocol.StateWaitingChunkRequest, nil
}

func stepSenderVerifyMerkle(s *protocol.Session) (protocol.TransferState, error) {
	root := merkle.Root_of_tree(merkle.BuildTree(s.Leaves))
	if err := chunk.SendRoot(s.Conn, root); err != nil {
		return 0, fmt.Errorf("sending merkle root: %w", err)
	}
	if err := chunk.ReadFinalAck(s.Conn); err != nil {
		return 0, fmt.Errorf("waiting for final ack: %w", err)
	}
	fmt.Printf("Sent %d chunks, merkle root: %x\n", s.TotalChunks, root)
	return protocol.StateFinished, nil
}

// ----------------------------------- RECEIVER ------------------------------------

func RecieveFile(conn protocol.Stream) error {
	s := protocol.NewSession(conn, protocol.RoleReceiver)
	return protocol.Run(s, receiverSteps)
}

var receiverSteps = protocol.StepTable{
	protocol.StateIdle:                 stepReceiverIdle,
	protocol.StateReceiveHeader:        stepReceiverReceiveHeader,
	protocol.StateSendChunkRequest:     stepReceiverSendChunkRequest,
	protocol.StateWaitingChunkResponse: stepReceiverWaitChunkResponse,
	protocol.StateSendLotteryTicket:    stepReceiverSendLotteryTicket,
	protocol.StateWaitingKeyReveal:     stepReceiverWaitKeyReveal,
	protocol.StateVerifyChunk:          stepReceiverVerifyChunk,
	protocol.StateVerifyMerkle:         stepReceiverVerifyMerkle,
}

func stepReceiverIdle(s *protocol.Session) (protocol.TransferState, error) {
	return protocol.StateReceiveHeader, nil
}

func stepReceiverReceiveHeader(s *protocol.Session) (protocol.TransferState, error) {
	header, err := chunk.ReadHeader(s.Conn)
	if err != nil {
		return 0, fmt.Errorf("reading header: %w", err)
	}

	s.FileID = header.FileID
	s.FileName = header.Name
	s.FileSize = uint64(header.FileSize)
	s.TotalChunks = header.Reps

	os.MkdirAll("./received/", 0775)
	file, err := os.Create("./received/" + header.Name)
	if err != nil {
		return 0, fmt.Errorf("creating output file: %w", err)
	}
	s.File = file

	if s.TotalChunks == 0 {
		// Normally VerifyMerkle's defer closes the file; since we're
		// skipping straight to Finished (no step runs for it), close here.
		if err := s.File.Close(); err != nil {
			return 0, fmt.Errorf("closing empty output file: %w", err)
		}
		return protocol.StateFinished, nil
	}

	fmt.Printf("Reps: %d, name: %s, fileID: %x\n", header.Reps, header.Name, header.FileID)

	return protocol.StateSendChunkRequest, nil
}

func stepReceiverSendChunkRequest(s *protocol.Session) (protocol.TransferState, error) {
	if err := chunk.SendChunkRequest(s.Conn, s.CurrentChunk); err != nil {
		return 0, fmt.Errorf("sending chunk request %d: %w", s.CurrentChunk, err)
	}
	return protocol.StateWaitingChunkResponse, nil
}

// this is basically reading the chunk response, and then storing it into the pending chunk in the session
func stepReceiverWaitChunkResponse(s *protocol.Session) (protocol.TransferState, error) {
	c, err := chunk.ReadChunkResponse(s.Conn, s.FileID)
	if err != nil {
		return 0, fmt.Errorf("reading chunk response %d: %w", s.CurrentChunk, err)
	}
	if c.Index != s.CurrentChunk {
		return 0, fmt.Errorf("out-of-order chunk response: want %d, got %d", s.CurrentChunk, c.Index)
	}
	s.PendingChunk = c
	return protocol.StateSendLotteryTicket, nil
}

func stepReceiverSendLotteryTicket(s *protocol.Session) (protocol.TransferState, error) {
	if err := chunk.SendLotteryTicket(s.Conn, s.CurrentChunk); err != nil {
		return 0, fmt.Errorf("sending lottery ticket %d: %w", s.CurrentChunk, err)
	}
	return protocol.StateWaitingKeyReveal, nil
}

func stepReceiverWaitKeyReveal(s *protocol.Session) (protocol.TransferState, error) {
	idx, key, err := chunk.ReadKeyReveal(s.Conn)
	if err != nil {
		return 0, fmt.Errorf("reading key reveal %d: %w", s.CurrentChunk, err)
	}
	if idx != s.CurrentChunk {
		return 0, fmt.Errorf("key reveal for wrong chunk: want %d, got %d", s.CurrentChunk, idx)
	}
	s.PendingChunk.Key = key
	return protocol.StateVerifyChunk, nil
}

func stepReceiverVerifyChunk(s *protocol.Session) (protocol.TransferState, error) {
	c := s.PendingChunk

	plaintext, err := utils.DecryptAndCheck(c)
	if err != nil {
		return 0, err
	}

	c.Leaf = merkle.GenerateLeaf(c)
	s.Leaves = append(s.Leaves, c.Leaf)

	if _, err := s.File.Write(plaintext); err != nil {
		return 0, fmt.Errorf("writing chunk %d to disk: %w", s.CurrentChunk, err)
	}

	last := s.IsLastChunk()

	s.PendingChunk = nil

	if last {
		return protocol.StateVerifyMerkle, nil
	}

	s.AdvanceChunk()

	return protocol.StateSendChunkRequest, nil
}

func stepReceiverVerifyMerkle(s *protocol.Session) (protocol.TransferState, error) {
	defer s.File.Close()

	remoteRoot, err := chunk.ReadRoot(s.Conn)
	if err != nil {
		return 0, fmt.Errorf("reading merkle root: %w", err)
	}

	localRoot := merkle.Root_of_tree(merkle.BuildTree(s.Leaves))
	if !bytes.Equal(localRoot, remoteRoot) {
		return 0, fmt.Errorf("merkle root mismatch: local=%x remote=%x", localRoot, remoteRoot)
	}
	fmt.Printf("Merkle root verified: %x\n", localRoot)

	if err := chunk.SendFinalAck(s.Conn); err != nil {
		return 0, fmt.Errorf("sending final ack: %w", err)
	}
	return protocol.StateFinished, nil
}

// ---------------------------------------------------------------------------------------------------------------
// THIS IS THE OLD FUNCTION WHERE ALL OF THE DATA WAS BEING SENT ONE AFTER THE OTHER, AND NO STATES WERE IMPLEMENTED, THE SAME BIG FUNCTION WRITTEN HERE BELOW HAVE BEEN BROKEN DOWN INTO SMALLER FUNCTIONS AND WRITTEN ABOVE

// func RecieveFile(conn net.Conn) error {
// 	fmt.Println("Received a request: " + conn.RemoteAddr().String())

// 	sentinel := make([]byte, 1)
// 	if _, err := io.ReadFull(conn, sentinel); err != nil {
// 		return fmt.Errorf("couldn't read header sentinel: %w", err)
// 	}

// 	buf := make([]byte, 4)
// 	if _, err := io.ReadFull(conn, buf); err != nil {
// 		return fmt.Errorf("couldn't read reps: %w", err)
// 	}
// 	reps := binary.BigEndian.Uint32(buf)

// 	fileID := make([]byte, protocol.HashSize)
// 	if _, err := io.ReadFull(conn, fileID); err != nil {
// 		return fmt.Errorf("couldn't read fileID: %w", err)
// 	}

// 	if _, err := io.ReadFull(conn, buf); err != nil {
// 		return fmt.Errorf("couldn't read name length: %w", err)
// 	}
// 	nameBuf := make([]byte, binary.BigEndian.Uint32(buf))
// 	if _, err := io.ReadFull(conn, nameBuf); err != nil {
// 		return fmt.Errorf("couldn't read name: %w", err)
// 	}
// 	name := string(nameBuf)

// 	fmt.Printf("Reps: %d, name: %s, fileID: %x\n", reps, name, fileID)
// 	conn.Write([]byte("Header of SendFile Received"))

// 	file, err := os.Create("./received/" + name)
// 	if err != nil {
// 		return fmt.Errorf("error creating output file: %w", err)
// 	}
// 	defer file.Close()

// 	var leaves [][]byte
// 	for i := 0; i < int(reps); i++ {
// 		c, err := recvChunkFromWire(conn, fileID)
// 		if err != nil {
// 			return fmt.Errorf("couldn't read chunk %d: %w", i, err)
// 		}

// 		if _, err := utils.DecryptChunk(c); err != nil {
// 			return fmt.Errorf("couldn't decrypt chunk %d: %w", i, err)
// 		}

// 		if !bytes.Equal(utils.ComputeResponseCommitment(c), c.HResp) {
// 			return fmt.Errorf("H_resp mismatch on chunk %d: integrity check failed", i)
// 		}

// 		c.Leaf = merkle.GenerateLeaf(c)
// 		leaves = append(leaves, c.Leaf)

// 		if _, err := file.Write(c.Plaintext); err != nil {
// 			return fmt.Errorf("couldn't write chunk %d to disk: %w", i, err)
// 		}
// 	}

// 	rootSentinel := make([]byte, 1)
// 	if _, err := io.ReadFull(conn, rootSentinel); err != nil {
// 		return fmt.Errorf("couldn't read root sentinel: %w", err)
// 	}
// 	remoteRoot := make([]byte, protocol.HashSize)
// 	if _, err := io.ReadFull(conn, remoteRoot); err != nil {
// 		return fmt.Errorf("couldn't read merkle root: %w", err)
// 	}

// 	localRoot := merkle.Root_of_tree(merkle.BuildTree(leaves))
// 	if bytes.Equal(localRoot, remoteRoot) {
// 		fmt.Printf("Merkle root verified: %x\n", localRoot)
// 	} else {
// 		fmt.Printf("MERKLE ROOT MISMATCH! local=%x remote=%x\n", localRoot, remoteRoot)
// 	}

// 	conn.Write([]byte(time.Now().UTC().Format("Monday, 02-Jan-06 15:04:05 IST")))
// 	return nil
// }

// // Wire format matches chunk.sendChunkOnWire:
// // sentinel(1)=0 | index(4) | ctLen(4) | ciphertext | key(32) | nonce(12) | hresp(32)
// func recvChunkFromWire(conn net.Conn, fileID []byte) (*protocol.Chunk, error) {
// 	sentinel := make([]byte, 1)
// 	if _, err := io.ReadFull(conn, sentinel); err != nil {
// 		return nil, err
// 	}

// 	buf := make([]byte, 4)
// 	if _, err := io.ReadFull(conn, buf); err != nil {
// 		return nil, err
// 	}
// 	index := binary.BigEndian.Uint32(buf)

// 	if _, err := io.ReadFull(conn, buf); err != nil {
// 		return nil, err
// 	}
// 	ciphertext := make([]byte, binary.BigEndian.Uint32(buf))
// 	if _, err := io.ReadFull(conn, ciphertext); err != nil {
// 		return nil, err
// 	}

// 	key := make([]byte, protocol.KeySize)
// 	if _, err := io.ReadFull(conn, key); err != nil {
// 		return nil, err
// 	}
// 	nonce := make([]byte, protocol.NonceSize)
// 	if _, err := io.ReadFull(conn, nonce); err != nil {
// 		return nil, err
// 	}
// 	hresp := make([]byte, protocol.HashSize)
// 	if _, err := io.ReadFull(conn, hresp); err != nil {
// 		return nil, err
// 	}

// 	return &protocol.Chunk{
// 		FileID: fileID, Index: index, Length: uint32(len(ciphertext)),
// 		Ciphertext: ciphertext, Key: key, Nonce: nonce, HResp: hresp,
// 	}, nil
// }

// -------------------------------------------------------------------------------------------------------------

// THIS IS THE OLD FUNCTION WITHOUT THE CHUNK STRUCT

// func RecieveFile(conn net.Conn) error {
// 	fmt.Println("Received a request: " + conn.RemoteAddr().String())

// 	// OLD WAY OF READING THE HEADER (using read)

// 	// headerBuffer := make([]byte, 1024)

// 	// n, err := conn.Read(headerBuffer)
// 	// fmt.Println("The header size is actually", n)

// 	// if err != nil {
// 	// 	log.Fatal("Couldnt read header Buffer", err)
// 	// }

// 	// var name string
// 	// var reps uint32

// 	// if headerBuffer[0] == byte(1) && headerBuffer[n-1] == byte(0) {
// 	// 	reps = binary.BigEndian.Uint32(headerBuffer[1:5])
// 	// 	lengthOfName := binary.BigEndian.Uint32(headerBuffer[5:9])
// 	// 	name = string(headerBuffer)[9 : 9+lengthOfName]
// 	// } else {
// 	// 	log.Fatal("Invalid header")
// 	// }

// 	// NEW WAY OF READING THE HEADER (using .ReadFull)  // This is much better since it takes care if the tcp breaks up the data while sending, and doesnt send it in chunks

// 	sentinel := make([]byte, 1)
// 	if _, err := io.ReadFull(conn, sentinel); err != nil {
// 		log.Fatal("Couldn't read sentinel", err)
// 	}

// 	buf := make([]byte, 4)
// 	if _, err := io.ReadFull(conn, buf); err != nil {
// 		log.Fatal("Couldn't read reps", err)
// 	}

// 	reps := binary.BigEndian.Uint32(buf)

// 	fileID := make([]byte, protocol.HashSize)
// 	if _, err := io.ReadFull(conn, fileID); err != nil {
// 		return fmt.Errorf("couldn't read fileID: %w", err)
// 	}

// 	if _, err := io.ReadFull(conn, buf); err != nil {
// 		log.Fatal("Couldn't read name length", err)
// 	}
// 	lengthOfName := binary.BigEndian.Uint32(buf)

// 	nameBuf := make([]byte, lengthOfName)
// 	if _, err := io.ReadFull(conn, nameBuf); err != nil {
// 		log.Fatal("Couldn't read name", err)
// 	}
// 	name := string(nameBuf)

// 	fmt.Printf("Reps: %d, name: %s, fileID: %x\n", reps, name, fileID)
// 	conn.Write([]byte("Header of SendFile Received"))

// 	file, err := os.Create("./received/" + name)

// 	if err != nil {
// 		log.Fatal("Error in creating a new folder", err)
// 	}

// 	defer file.Close()

// 	var leaves [][]byte

// 	// dataBuffer := make([]byte, 1024)

// 	for i := 0; i < int(reps); i++ {

// 		// OLD WAY OF READING THE SEGMENT

// 		// noofbytesreadperrep, err := conn.Read(dataBuffer)
// 		// fmt.Println(i, noofbytesreadperrep)

// 		// if err != nil && err != io.EOF {
// 		// 	log.Fatal(err)
// 		// }

// 		// if dataBuffer[0] == byte(0) && dataBuffer[noofbytesreadperrep-1] == byte(1) {
// 		// 	segmentNumber := dataBuffer[1:5]
// 		// 	fmt.Printf("Segment Number: %d\n", binary.BigEndian.Uint32(segmentNumber))
// 		// 	lengthOfDataSegment := binary.BigEndian.Uint32(dataBuffer[5:9])
// 		// 	// fmt.Println(hex.EncodeToString(dataBuffer[9 : 9+lengthOfDataSegment]))
// 		// 	file.Write(dataBuffer[9 : 9+lengthOfDataSegment])
// 		// } else {
// 		// 	log.Fatal("Invalid dataSegment")
// 		// }

// 		buf := make([]byte, 4)

// 		sentinel := make([]byte, 1)
// 		if _, err := io.ReadFull(conn, sentinel); err != nil {
// 			log.Fatal("Couldn't read segment sentinel", err)
// 		}

// 		if _, err := io.ReadFull(conn, buf); err != nil {
// 			log.Fatal("Couldn't read segment number", err)
// 		}
// 		// segmentNumber := binary.BigEndian.Uint32(buf)

// 		if _, err := io.ReadFull(conn, buf); err != nil {
// 			log.Fatal("Couldn't read segment data length", err)
// 		}
// 		lengthOfDataSegment := binary.BigEndian.Uint32(buf)

// 		dataBuf := make([]byte, lengthOfDataSegment)
// 		if _, err := io.ReadFull(conn, dataBuf); err != nil {
// 			log.Fatal("Couldn't read segment data", err)
// 		}

// 		// fmt.Printf("Segment Number: %d \n", segmentNumber)

// 		file.Write(dataBuf)

// 		// fmt.Printf("Recieved %dth rep segment data\n", i)

// 	}

// 	time := time.Now().UTC().Format("Monday, 02-Jan-06 15:04:05 IST")

// 	conn.Write([]byte(time))

// 	file.Close()
// }

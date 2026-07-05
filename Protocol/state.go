package protocol

type TransferState uint8

const (

	// Initial State
	StateIdle TransferState = iota

	// Header Exchange
	StateSendHeader
	StateReceiveHeader

	// Chunk Handshake
	// Sender
	StateWaitingChunkRequest
	StateSendChunkResponse
	StateWaitingLotteryTicket
	StateSendKeyReveal

	// Receiver
	StateSendChunkRequest
	StateWaitingChunkResponse
	StateSendLotteryTicket
	StateWaitingKeyReveal

	// Verification
	StateVerifyChunk
	StateVerifyMerkle

	// Completion
	StateFinished

	// Error
	StateError
)

var validTransitions = map[TransferState][]TransferState{

	StateIdle: {
		StateSendHeader,
		StateReceiveHeader,
	},

	// Sender

	StateSendHeader: {
		StateWaitingChunkRequest,
		StateFinished, // empty file: nothing to send or verify, done immediately
	},

	StateWaitingChunkRequest: {
		StateSendChunkResponse,
	},

	StateSendChunkResponse: {
		StateWaitingLotteryTicket,
	},

	StateWaitingLotteryTicket: {
		StateSendKeyReveal,
	},

	StateSendKeyReveal: {

		StateWaitingChunkRequest,

		StateVerifyMerkle,
	},

	// Receiver

	StateReceiveHeader: {
		StateSendChunkRequest,
		StateFinished, // empty file: nothing to receive or verify, done immediately
	},

	StateSendChunkRequest: {
		StateWaitingChunkResponse,
	},

	StateWaitingChunkResponse: {
		StateSendLotteryTicket,
	},

	StateSendLotteryTicket: {
		StateWaitingKeyReveal,
	},

	StateWaitingKeyReveal: {
		StateVerifyChunk,
	},

	StateVerifyChunk: {

		StateSendChunkRequest,

		StateVerifyMerkle,
	},

	StateVerifyMerkle: {
		StateFinished,
	},

	StateFinished: {},

	StateError: {},
}

// Stringer function : just takes in a transfer state and outputs a string corr to its name

func (t TransferState) String() string {
	names := map[TransferState]string{
		StateIdle:                 "Idle",
		StateSendHeader:           "SendHeader",
		StateReceiveHeader:        "ReceiveHeader",
		StateWaitingChunkRequest:  "WaitingChunkRequest",
		StateSendChunkResponse:    "SendChunkResponse",
		StateWaitingLotteryTicket: "WaitingLotteryTicket",
		StateSendKeyReveal:        "SendKeyReveal",
		StateSendChunkRequest:     "SendChunkRequest",
		StateWaitingChunkResponse: "WaitingChunkResponse",
		StateSendLotteryTicket:    "SendLotteryTicket",
		StateWaitingKeyReveal:     "WaitingKeyReveal",
		StateVerifyChunk:          "VerifyChunk",
		StateVerifyMerkle:         "VerifyMerkle",
		StateFinished:             "Finished",
		StateError:                "Error",
	}
	if n, ok := names[t]; ok {
		return n
	}
	return "Unknown"
}

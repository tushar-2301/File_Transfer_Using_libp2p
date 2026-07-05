package protocol

type MetaData struct {
	Name     string
	FileSize uint32 // this is not just kept int, and specified as 32 so that it doesnt depend on the system, this can cause some problems else
	Reps     uint32 // imp to also keep the fieldnames starting with Caps
	FileID   []byte // Keccak-256 id for this transfer, needed by receiver too
}

type Chunk struct {
	FileID []byte

	Index uint32

	Length uint32

	Plaintext []byte

	Ciphertext []byte

	Key []byte

	Nonce []byte

	HResp []byte

	Leaf []byte
}

func NewChunk(fileID []byte, index uint32, data []byte) *Chunk {
	return &Chunk{

		FileID: fileID,

		Index: index,

		Length: uint32(len(data)),

		Plaintext: data,
	}
}

const (
	HOST                   = "0.0.0.0"
	PORT                   = "9001"
	TYPE                   = "tcp"
	FILE_TO_BE_TRANSFERRED = "/home/tushar/Cipher/file_transfer_using_tcp/File_to_be_sent/trial.png"

	KeySize   = 32 // AES-256 // used in GenerateRandomKey() func
	NonceSize = 12 // GCM standard // used in GenerateRandomKey() func

	// yeh dono bas aise hi diye hai, just for info, changing this changes nothing
	HashSize  = 32    // Keccak-256 output size
	ChunkSize = 32768 // 32 KB
)

package protocol

import "io"

// Stream is satisfied by net.Conn today and by libp2p's network.Stream
// later. Nothing else in this package should import "net" directly.
type Stream interface {
	io.Reader
	io.Writer
	io.Closer
}

// An interface stores no data and provides no implementation. It only defines a set of required methods.
// You cannot create an instance of an interface directly because it doesn't describe what something is; it describes what something can do.

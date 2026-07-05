// Package p2p centralizes everything libp2p-specific: identity
// (persistent Ed25519 keypair -> stable PeerID), host construction, and
// the protocol ID used for this app. Nothing in Controllers, Chunk,
// Merkle, Utils, or Protocol needs to know libp2p exists — they only
// ever see protocol.Stream (io.Reader + io.Writer + io.Closer), which
// libp2p's network.Stream already satisfies.
package p2p

import (
	"os"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
)

// ProtocolID identifies this application's protocol on the libp2p
// multistream-select layer. Think of it as the libp2p equivalent of a
// well-known TCP port + application-level handshake, combined.
const ProtocolID = "/file-transfer/1.0.0"

// LoadOrCreateIdentity reads an Ed25519 private key from keyPath, or
// generates a new one and persists it there if none exists yet.
//
// This matters because a libp2p PeerID is derived from the public key.
// Without persisting it, the server would get a brand new PeerID (and
// thus a new address to dial) every time it restarts, which is
// annoying for clients that hardcode/save the server's multiaddr.
func LoadOrCreateIdentity(keyPath string) (crypto.PrivKey, error) {
	// if the key is stored in the given keyPath, then read that, unmarshal it or convert it into a key obj in go, and then simply use that
	if data, err := os.ReadFile(keyPath); err == nil {
		return crypto.UnmarshalPrivateKey(data)
	}

	// if the key is not alr present create a new key, marshal it, and store it in a file
	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1) // this basically generates a private , public key (of the default size since we gave -1), even though here we are ignoring the public key
	if err != nil {
		return nil, err
	}

	// marshaling is basically serialization ie. this converts the key obj in go to []byte
	data, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, err
	}

	// 0600: this is a private key, keep it readable only by the owner.
	if err := os.WriteFile(keyPath, data, 0600); err != nil {
		return nil, err
	}

	return priv, nil
}

// GenerateEphemeralIdentity creates a fresh, unpersisted Ed25519 keypair.
// Fine for a client whose PeerID doesn't need to stay the same across
// runs — only the server side needs LoadOrCreateIdentity's persistence.
func GenerateEphemeralIdentity() (crypto.PrivKey, error) {
	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	return priv, err
}

// NewHost builds a libp2p host.
//
// listenAddrs is nil/empty for a client that only dials out (it still
// gets an ephemeral listen address automatically via libp2p defaults
// unless NoListenAddrs is set — for a pure client we suppress that).
func NewHost(priv crypto.PrivKey, listenAddrs ...string) (host.Host, error) { // notice the priv is the private key and its type is crypto.PrivKey, nothing very imp but just notice

	// these are options to be provided while creating a new host
	opts := []libp2p.Option{
		libp2p.Identity(priv), // tells libp2p to use the given key, or else it will create its own
		libp2p.NATPortMap(),   // best-effort UPnP/NAT-PMP port mapping for reachability
	}

	// adds the given listening addrs to the opts, which would be given during creating a new host. If there is no listening addr, given to this host, then it means that there is no use keeping the listening socket open for this port, and we set it to libp2p.NoListenAddrs, which means that this host can only dial in other hosts, but it wont accept any incoming requests
	if len(listenAddrs) > 0 {
		opts = append(opts, libp2p.ListenAddrStrings(listenAddrs...)) // equivalent to net.Listen()
	} else {
		// Pure outbound client: don't bother opening any listen socket.
		opts = append(opts, libp2p.NoListenAddrs)
	}

	return libp2p.New(opts...)
}

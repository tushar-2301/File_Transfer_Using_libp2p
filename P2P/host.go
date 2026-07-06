// Package p2p centralizes everything libp2p-specific: identity
// (persistent Ed25519 keypair -> stable PeerID), host construction, and
// the protocol ID used for this app. Nothing in Controllers, Chunk,
// Merkle, Utils, or Protocol needs to know libp2p exists — they only
// ever see protocol.Stream (io.Reader + io.Writer + io.Closer), which
// libp2p's network.Stream already satisfies.
package p2p

import (
	"fmt"
	"os"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/host/autorelay"
	"github.com/multiformats/go-multiaddr"
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

// StaticRelayAddrs parses relay multiaddrs (each one INCLUDING the
// "/p2p/<PeerID>" suffix, e.g. "/ip4/1.2.3.4/tcp/4001/p2p/12D3KooW...")
// into the []peer.AddrInfo shape libp2p.EnableAutoRelayWithStaticRelays
// wants. This is how a Render relay address or a public test-relay
// address (both just strings from a config/env var) get fed into
// AutoRelay as candidates.
//
// Multiple strings that happen to belong to the same relay PeerID are
// NOT merged here — each becomes its own AddrInfo. AutoRelay is fine
// with that; it just sees a slightly longer candidate list.
func StaticRelayAddrs(addrs []string) ([]peer.AddrInfo, error) {
	infos := make([]peer.AddrInfo, 0, len(addrs))
	for _, a := range addrs {
		maddr, err := multiaddr.NewMultiaddr(a)
		if err != nil {
			return nil, fmt.Errorf("invalid relay multiaddr %q: %w", a, err)
		}
		info, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			return nil, fmt.Errorf("relay multiaddr %q is missing /p2p/<PeerID>: %w", a, err)
		}
		infos = append(infos, *info)
	}
	return infos, nil
}

// NewHost builds a libp2p host.
//
// listenAddrs is nil/empty for a client that only dials out (it still
// gets an ephemeral listen address automatically via libp2p defaults
// unless NoListenAddrs is set — for a pure client we suppress that).
//
// staticRelays is the AutoRelay candidate pool (Phase 2): pass both the
// public libp2p test relay and your Render relay here. AutoRelay treats
// this as a pool it holds reservations across and backs off from
// whichever candidates don't respond — nil/empty just means "no relay
// support for this host" (e.g. the relay binary itself doesn't need it).
func NewHost(priv crypto.PrivKey, listenAddrs []string, staticRelays []peer.AddrInfo) (host.Host, error) {

	// these are options to be provided while creating a new host
	opts := []libp2p.Option{
		libp2p.Identity(priv), // tells libp2p to use the given key, or else it will create its own
		libp2p.NATPortMap(),   // best-effort UPnP/NAT-PMP port mapping for reachability
		libp2p.EnableRelay(),
		libp2p.ForceReachabilityPrivate(), // newly added
		// EnableRelay lets THIS host make outbound connections through a
		// relay and accept inbound relayed connections — it's the
		// "can use a relay" switch, as opposed to EnableRelayService
		// (relay/main.go), which is the "can BE a relay for others"
		// switch. It's on by default in libp2p, but we set it
		// explicitly since it's load-bearing for Phase 2.
		// lip2p.EnableRelayService() --> is used to configure the  current host to act as a relay
		// libp2p.EnableRelay() --> is used to tell that the current host can use a relay to connect with others
	}

	// adds the given listening addrs to the opts, which would be given during creating a new host. If there is no listening addr, given to this host, then it means that there is no use keeping the listening socket open for this port, and we set it to libp2p.NoListenAddrs, which means that this host can only dial in other hosts, but it wont accept any incoming requests
	if len(listenAddrs) > 0 {
		opts = append(opts, libp2p.ListenAddrStrings(listenAddrs...)) // equivalent to net.Listen()
	} else {
		// Pure outbound client: don't bother opening any listen socket.
		opts = append(opts, libp2p.NoListenAddrs)
	}

	// AutoRelay: when this host discovers (via AutoNAT) that it's not
	// publicly reachable, it reserves a slot on one of these candidates
	// and starts advertising a relayed address through it, so the other
	// peer has *something* dialable even before/if hole punching (Phase
	// 3) succeeds.
	if len(staticRelays) > 0 {
		opts = append(opts, libp2p.EnableAutoRelayWithStaticRelays(
			staticRelays,
			autorelay.WithBootDelay(0),     // don't wait before trying
			autorelay.WithMinCandidates(1), // 1 candidate is enough to act on
			autorelay.WithNumRelays(1),     // we only need/have 1 relay anyway
		))
	}
	// basicaly the above line is doing "Monitor whether I'm publicly reachable. If AutoNAT determines I'm behind a NAT, automatically connect to one of these known relay servers, reserve a relay slot, and advertise a relay address so other peers can still reach me. If I later become directly reachable (for example, after successful hole punching), libp2p can prefer the direct connection instead."

	return libp2p.New(opts...)
}

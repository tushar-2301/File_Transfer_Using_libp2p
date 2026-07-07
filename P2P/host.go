// Package p2p centralizes everything libp2p-specific: identity
// (persistent Ed25519 keypair -> stable PeerID), host construction, and
// the protocol ID used for this app. Nothing in Controllers, Chunk,
// Merkle, Utils, or Protocol needs to know libp2p exists — they only
// ever see protocol.Stream (io.Reader + io.Writer + io.Closer), which
// libp2p's network.Stream already satisfies.
package p2p

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	circuit "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	ws "github.com/libp2p/go-libp2p/p2p/transport/websocket"
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
func NewHost(ctx context.Context, priv crypto.PrivKey, listenAddrs []string, staticRelays []peer.AddrInfo) (host.Host, error) {

	// these are options to be provided while creating a new host
	opts := []libp2p.Option{
		libp2p.Identity(priv), // tells libp2p to use the given key, or else it will create its own
		libp2p.NATPortMap(),   // best-effort UPnP/NAT-PMP port mapping for reachability
		// EnableRelay lets THIS host make outbound connections through a
		// relay and accept inbound relayed connections — it's the
		// "can use a relay" switch, as opposed to EnableRelayService
		// (relay/main.go), which is the "can BE a relay for others"
		// switch. It's on by default in libp2p, but we set it
		// explicitly since it's load-bearing for Phase 2.
		// lip2p.EnableRelayService() --> is used to configure the  current host to act as a relay
		// libp2p.EnableRelay() --> is used to tell that the current host can use a relay to connect with others
		libp2p.EnableRelay(),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Transport(quic.NewTransport),
		libp2p.Transport(ws.New),

		// libp2p.ForceReachabilityPrivate(), // this is very imppppp

		// AutoRelay only starts trying to reserve a slot on your static relays once it's confirmed (via AutoNAT) that this host is NOT publicly reachable. AutoNAT confirms that by having other peers dial back to you and report success/failure — which requires inbound connection attempts from peers who also run AutoNAT. Your Server, sitting alone with zero peers ever having connected to it, has no way to get that confirmation. So AutoRelay just sits there indefinitely in "reachability unknown" limbo, never triggering a reservation — no error, no timeout, just silence

		// once a relayed connection to a peer exists, this turns on the DCUtR (Direct Connection Upgrade through Relay) protocol
		// — both sides exchange their observed/candidate addresses over the relayed stream and attempt a synchronized ("hole punch") direct dial at each other. If it succeeds, libp2p ends up with
		// a second, direct connection to the same peer, and the swarm
		// prefers that direct connection for any NEW streams from then on — the relay drops out of the data path without either side having to change any application code.
		libp2p.EnableHolePunching(),
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
	// if len(staticRelays) > 0 {
	// 	opts = append(opts, libp2p.EnableAutoRelayWithStaticRelays(
	// 		staticRelays,
	// 		// these 3 .With were added while debugging, since after running server.go it was not printing the public addr required to be given to the client.go, and neither was it giving any error it was just silently failing
	// 		autorelay.WithBootDelay(0),     // don't wait before trying
	// 		autorelay.WithMinCandidates(1), // 1 candidate is enough to act on
	// 		autorelay.WithNumRelays(1),     // we only need/have 1 relay anyway
	// 	))
	// }
	// basicaly the above line is doing "Monitor whether I'm publicly reachable. If AutoNAT determines I'm behind a NAT, automatically connect to one of these known relay servers, reserve a relay slot, and advertise a relay address so other peers can still reach me. If I later become directly reachable (for example, after successful hole punching), libp2p can prefer the direct connection instead."

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, err
	}

	// Deterministic relay reservation, kept alive for the life of the
	// process — see keepReservationAlive below for why a one-shot
	// Reserve() isn't enough on its own.
	for _, relay := range staticRelays {
		if err := h.Connect(ctx, relay); err != nil {
			fmt.Printf("could not connect to relay %s: %v\n", relay.ID, err)
			continue
		}
		rsvp, err := circuit.Reserve(ctx, h, relay)
		if err != nil {
			fmt.Printf("could not reserve slot on relay %s: %v\n", relay.ID, err)
			continue
		}
		fmt.Printf("reserved a slot on relay %s (expires %s)\n", relay.ID, rsvp.Expiration)
		go keepReservationAlive(h, relay, rsvp)
	}

	return h, nil

}

// isRelayedAddr reports whether a connection's remote multiaddr goes through a circuit-v2 relay hop (contains "/p2p-circuit") as opposed to being a direct address. This is the simplest reliable way to tell a relayed connection apart from a direct one without depending on go-libp2p's internal holepunch tracing types.
func isRelayedAddr(addr multiaddr.Multiaddr) bool {
	return strings.Contains(addr.String(), "/p2p-circuit")
}

// ConnKind describes what a connection to a peer currently looks like.
type ConnKind int

const (
	NoConn ConnKind = iota
	Relayed
	Direct
)

// connKindToPeer inspects the swarm's current connections to p and
// reports the "best" one: Direct if any non-relayed connection exists,
// Relayed if only circuit connections exist, NoConn if there's nothing.
func connKindToPeer(h host.Host, p peer.ID) ConnKind {
	conns := h.Network().ConnsToPeer(p) // This returns every connection currently open to that peer
	// if the host is connected to the peer, then the peer would be present in the network of host h, thus h.Network()
	if len(conns) == 0 {
		return NoConn
	}
	best := Relayed
	for _, c := range conns {
		if !isRelayedAddr(c.RemoteMultiaddr()) { // we basically check for each of the conn in conns if its relayed/ direct
			return Direct
		}
	}
	return best
}

// This is just the monitoring function
// WatchForDirectUpgrade polls the connections to peer p and logs the moment a relayed connection is joined (or replaced) by a direct one i.e. "hole punch succeeded, relay is out of the data path" moment

// It also logs a StartHolePunch-equivalent line the first time it sees a relayed connection, and gives up (logging that hole punching didn't complete) after timeout, in which case the relayed connection simply keeps serving as the fallback path.

// Runs in its own goroutine; safe to call and forget.
func WatchForDirectUpgrade(ctx context.Context, h host.Host, p peer.ID, timeout time.Duration) {
	go func() {
		deadline := time.After(timeout)
		ticker := time.NewTicker(300 * time.Millisecond)
		defer ticker.Stop()

		announcedRelayed := false // this is just a flag ensuring that if the StartHolePunch msg has been printed once, and if its printed once do not print again or else it would keep printing that every 300ms

		for {
			select {
			case <-ctx.Done(): // if the ctx is cancelled then Stop monitoring
				return
			case <-deadline: // timed out
				if !announcedRelayed {
					return // never even got a relayed connection; nothing to report
				}
				if connKindToPeer(h, p) != Direct {
					known := h.Peerstore().Addrs(p)
					log.Printf("[holepunch] timed out waiting for a direct connection to %s; staying on relayed connection", p)
					log.Printf("[holepunch] known/observed addresses for %s: %v", p, known)
				}
				return
			case <-ticker.C:
				switch connKindToPeer(h, p) {
				case Relayed:
					if !announcedRelayed {
						announcedRelayed = true
						log.Printf("[holepunch] StartHolePunch: connected to %s via relay, attempting direct upgrade...", p)
					}
				case Direct:
					if announcedRelayed {
						log.Printf("[holepunch] EndHolePunch: direct connection to %s established — relay is now out of the data path for this session", p)
					} else {
						log.Printf("[holepunch] connected to %s directly (no relay hop needed)", p)
					}
					return
				case NoConn:
					// not connected yet; keep polling until deadline
				}
			}
		}
	}()
}

// ClientListenAddrs returns a listen address for a peer that otherwise has no need to be dialed directly by a human (e.g. the CLI client).
// It listens on an OS-assigned ephemeral TCP port on all interfaces.

// hole punching is a *simultaneous* dial from both sides. A host built with libp2p.NoListenAddrs has no listening socket at all, so it can't be the target of the inbound half of that simultaneous dial, and DCUtR can't upgrade the connection — it would stay relayed forever. Giving even a pure "client" role an ephemeral listener fixes that without requiring the user to pick or forward a port.
func ClientListenAddrs() []string {
	return []string{
		"/ip4/0.0.0.0/tcp/0",
		"/ip4/0.0.0.0/udp/0/quic-v1",
	}
}

// keepReservationAlive re-reserves a relay slot shortly before it
// expires, for as long as this host is running. Without this, a
// long-lived server process ends up with a *stale* reservation: the
// process looks healthy, the Peer ID hasn't changed, but the relay
// has quietly forgotten about it, and every subsequent dial through
// /p2p-circuit/.../p2p/<serverID> fails with NO_RESERVATION.
func keepReservationAlive(h host.Host, relay peer.AddrInfo, rsvp *circuit.Reservation) {
	for {
		wait := time.Until(rsvp.Expiration) - 30*time.Second
		if wait < 5*time.Second {
			wait = 5 * time.Second
		}
		time.Sleep(wait)

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		newRsvp, err := circuit.Reserve(ctx, h, relay)
		cancel()
		if err != nil {
			log.Printf("[relay] failed to renew reservation on %s: %v — will retry shortly", relay.ID, err)
			time.Sleep(10 * time.Second)
			continue
		}
		rsvp = newRsvp
		log.Printf("[relay] renewed reservation on %s (expires %s)", relay.ID, rsvp.Expiration)
	}
}

// Command relay is the third binary the plan calls for: a bare libp2p
// host that runs nothing but the circuit-v2 relay service. It has zero
// awareness of CIPHER's packet semantics — ChunkRequest/ChunkResponse
// and everything else are opaque bytes to it. All it holds in memory is
// reservation state (who's currently parked here) and active-circuit
// state, none of which survives a restart.
//
// Run it once, somewhere with a real public IP (a Render web service,
// per the plan's Open Decisions), and give both peer nodes the printed
// multiaddr as a --relay flag / RELAY_ADDRS entry.
package main

import (
	p2p "file_transfer/P2P"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/libp2p/go-libp2p"
	relayv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
)

// Separate identity file from the Server's, so running both on the same
// box (or same Render instance during local testing) doesn't clash.
const identityKeyPath = "relay_identity.key"

func main() {
	priv, err := p2p.LoadOrCreateIdentity(identityKeyPath)
	if err != nil {
		log.Fatal("couldn't load/create relay identity: ", err)
	}

	// Render (and most PaaS providers) inject PORT at runtime and expect
	// the app to bind to it; fall back to a fixed port for local/VPS runs.
	port := os.Getenv("PORT")
	if port == "" {
		port = "4001"
	}

	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings(
			fmt.Sprintf("/ip4/0.0.0.0/tcp/%s/ws", port), // Accept connections on every interface
		),

		// Without it, your node is just a normal libp2p peer. With it, your node becomes a relay server

		// This relay serves no one but us, at demo scale, for sessions
		// capped by nothing but our own patience — so disabling the
		// default 2-minute-per-circuit / data-cap limit is a reasonable
		// call up front rather than something to debug later as a
		// mystery timeout mid-transfer, per the plan's Phase 2 note.
		libp2p.EnableRelayService(relayv2.WithInfiniteLimits()),

		// EnableRelayService only actually activates once AutoNAT
		// confirms this host is publicly reachable. Behind a PaaS
		// proxy that confirmation can be flaky or slow to arrive, and
		// this box IS publicly reachable by construction (that's the
		// whole point of deploying it) — so we tell libp2p to skip
		// the detection step and believe it immediately.
		libp2p.ForceReachabilityPublic(),

		// A relay's only job is being dialed; it never needs to dial
		// out through another relay itself.
		// Never use relay transport when I dial another peer
		libp2p.DisableRelay(),
	)
	if err != nil {
		log.Fatal("relay host creation failed: ", err)
	}
	defer h.Close()

	fmt.Println("Relay PeerID:", h.ID().String())
	fmt.Println("Relay listening on:")
	for _, addr := range h.Addrs() {
		fmt.Printf("  %s/p2p/%s\n", addr, h.ID())
	}
	fmt.Println("\nGive one of the addresses above (with /p2p/<PeerID>) to both peer nodes as a static relay candidate.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	fmt.Println(sig)
	fmt.Println("\nShutting down relay.")
}

package main

import (
	"context"
	"encoding/binary"
	controllers "file_transfer/Controllers"
	p2p "file_transfer/P2P"
	protocol "file_transfer/Protocol"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/multiformats/go-multiaddr"
)

// connLogger implements network.Notifiee just enough to kick off a
// WatchForDirectUpgrade goroutine every time a new connection to a peer
// shows up, so the server side (not just the dialing client side) prints
// the Phase 3 relayed -> direct transition in its own logs.
type connLogger struct {
	h host.Host
}

func (c *connLogger) Connected(_ network.Network, conn network.Conn) {
	p2p.WatchForDirectUpgrade(context.Background(), c.h, conn.RemotePeer(), 15*time.Second)
}
func (c *connLogger) Disconnected(network.Network, network.Conn)       {}
func (c *connLogger) Listen(network.Network, multiaddr.Multiaddr)      {}
func (c *connLogger) ListenClose(network.Network, multiaddr.Multiaddr) {}

// Keeping the key here means the server keeps the same PeerID (and thus
// the same dialable address) across restarts.
const identityKeyPath = "server_identity.key"

// splitNonEmpty splits a comma-separated env var into a clean []string,
// dropping empty entries so an unset/blank RELAY_ADDRS just means "no
// relay candidates" instead of one bogus empty-string entry.
func splitNonEmpty(csv string) []string {
	if csv == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func main() {

	priv, err := p2p.LoadOrCreateIdentity(identityKeyPath)
	if err != nil {
		log.Fatal("couldn't load/create identity: ", err)
	}

	// Listen on all interfaces, same PORT the TCP version used, just
	// expressed as a libp2p multiaddr instead of a bare net.Listen call.
	listenAddr := fmt.Sprintf("/ip4/0.0.0.0/tcp/%s", protocol.PORT)

	// RELAY_ADDRS: comma-separated relay multiaddrs, each including
	// /p2p/<PeerID> — e.g. the address relay/main.go prints on startup.
	// Leave it unset to run with no relay support at all (Phase 1 mode).
	staticRelays, err := p2p.StaticRelayAddrs(splitNonEmpty(os.Getenv("RELAY_ADDRS")))
	if err != nil {
		log.Fatal("bad RELAY_ADDRS: ", err)
	}

	// this creates a host with the given private key, and our given listenaddr, and some additional settings provided int he NewHost func
	h, err := p2p.NewHost(priv, []string{listenAddr}, staticRelays)
	if err != nil {
		log.Fatal("libp2p host creation failed: ", err)
	}
	defer h.Close()

	fmt.Println("Server PeerID:", h.ID().String())
	fmt.Println("Server is listening on:")

	// h.Addrs() returns all addresses on which this host is listening, the addr would be smth like /ip4/127.0.0.1/tcp/4001, this provides the info about the protocol, ip, port, but just giving this to the client wont be enough, bcoz the client needs the peerID of the server(or whatever to the other person that its trying to connect(btw there are no server and client in libp2p, all are just hosts))
	// So here we are creating the multiaddr which are required to be given to the client in order to connect to this server
	time.Sleep(15 * time.Second)
	for _, addr := range h.Addrs() {
		fmt.Printf("  %s/p2p/%s\n", addr, h.ID())
	}
	fmt.Println("\nGive one of the addresses above (with /p2p/<PeerID>) to the client.")

	// SetStreamHandler is the libp2p equivalent of the old Accept() loop:
	// libp2p calls HandleStream in its own goroutine per incoming stream,
	// exactly like `go HandleConn(conn)` did per incoming TCP connection.
	// It tells libp2p "Whenever somebody opens a stream for protocol p2p.ProtocolID, call HandleStream."
	h.SetStreamHandler(p2p.ProtocolID, HandleStream)

	// Phase 3: log the relayed->direct upgrade from the server side too.
	// Every time a new peer connects, watch its connection for up to 15s
	// to see if DCUtR manages to establish a direct connection alongside
	// (or instead of) the relayed one.
	h.Network().Notify(&connLogger{h: h})

	// Block until interrupted (Ctrl+C), instead of `for true { Accept() }`.
	sigCh := make(chan os.Signal, 1) // this is creating a channel of type (chan os.Signal) which is an interface representing an operating system signal. Also the buffer given is 1, so that we can at everytime store the last OS signal, without the buffer both the sender and receiver must rendezvous exactly at the same time.

	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM) // This does this that whenever the OS sends either SIGINT or SIGTERM, put that signal into sigCh
	// SIGINT is generated when you press Ctrl + C and SIGTERM is usually sent by another process, when it wants to kill this process

	// Now instead of these next 2 lines u could just write <-sigCh, bcoz it actually doesnt matter which signal was received

	//It means receive one value from the channel. But the catch here is that receiving from a channel blocks if the channel is empty, so until someone kills the process, this would be waiting for some value to be received
	sig := <-sigCh
	fmt.Println(sig)

	// and btw this is a better approach than an infinite loop since infinite loop uses cpu, while this uses zero CPU while waiting
	fmt.Println("\nShutting down.")
}

// HandleStream is the direct libp2p analogue of the old HandleConn(conn net.Conn).
func HandleStream(s network.Stream) {
	defer s.Close()

	fmt.Println("Received a stream from peer:", s.Conn().RemotePeer())

	buf := make([]byte, 4)

	if _, err := io.ReadFull(s, buf); err != nil {
		log.Println("Couldn't read typ in whattodoheader:", err)
		s.Reset()
		return
	}
	typ := binary.BigEndian.Uint32(buf)

	if _, err := io.ReadFull(s, buf); err != nil {
		log.Println("Couldn't read lengthOfPath in whattodoheader:", err)
		s.Reset()
		return
	}
	lengthOfPath := binary.BigEndian.Uint32(buf)

	pathBuf := make([]byte, lengthOfPath)
	if _, err := io.ReadFull(s, pathBuf); err != nil {
		log.Println("Couldn't read path in whattodoheader:", err)
		s.Reset()
		return
	}
	path := string(pathBuf)

	fmt.Printf("The typ is %d and path is %s : whattodoheader received correctly\n", typ, path)

	switch typ {

	case 0: // GET
		fmt.Println("Stream handler: GET, starting SendFile")
		if err := controllers.SendFile(path, s); err != nil {
			log.Println("SendFile failed:", err)
		}

	case 1: // POST
		fmt.Println("Stream handler: POST, starting RecieveFile")
		if err := controllers.RecieveFile(s); err != nil {
			log.Println("RecieveFile failed:", err)
		}

	default:
		fmt.Println("Unknown command")
	}
}

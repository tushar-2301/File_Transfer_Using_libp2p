package main

import (
	"context"
	"encoding/binary"
	controllers "file_transfer/Controllers"
	p2p "file_transfer/P2P"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

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

// RequestFile sends the "what to do" header (method + path) — same wire
// format as the TCP version, just written to a network.Stream instead of
// a *net.TCPConn, network.Stream satisfies io.Writer

func RequestFile(path string, s network.Stream, method string) {

	whattodoheaderBuffer := []byte{} // create a blank byte slice
	temp := make([]byte, 4)

	// 0 means GET and 1 means POST

	if method == "GET" {
		binary.BigEndian.PutUint32(temp, uint32(0))
		whattodoheaderBuffer = append(whattodoheaderBuffer, temp...)
	}
	if method == "POST" {
		binary.BigEndian.PutUint32(temp, uint32(1))
		whattodoheaderBuffer = append(whattodoheaderBuffer, temp...)
	}

	binary.BigEndian.PutUint32(temp, uint32(len(path)))
	whattodoheaderBuffer = append(whattodoheaderBuffer, temp...)
	whattodoheaderBuffer = append(whattodoheaderBuffer, []byte(path)...)

	if _, err := s.Write(whattodoheaderBuffer); err != nil { // 1. Sent the whattodoheader
		log.Fatal("Couldnt write the whattodoheaderBuffer", err)
	}

	fmt.Println("Successfully sent the whattodoheader from client.go")
}

func main() {

	if len(os.Args) < 4 {
		fmt.Println("Usage: client <GET|POST> <path> <server-multiaddr>")
		fmt.Println(`Example: client GET /remote/path/file.png "/ip4/1.2.3.4/tcp/9001/p2p/12D3KooW..."`)
		os.Exit(1)
	}

	// os.Args[1] is REQ Type and os.Args[2] is the path string

	method := strings.ToUpper(os.Args[1])
	path := os.Args[2]
	targetAddr := os.Args[3] // full multiaddr including /p2p/<PeerID>, printed by the server on startup

	// Client identity doesn't need to be stable across runs — a fresh
	// keypair each time is fine, it just becomes this run's PeerID.
	priv, err := p2p.GenerateEphemeralIdentity()
	if err != nil {
		log.Fatal("couldn't generate client identity: ", err)
	}

	// Same RELAY_ADDRS convention as the server — comma-separated
	// multiaddrs, each including /p2p/<PeerID>.
	staticRelays, err := p2p.StaticRelayAddrs(splitNonEmpty(os.Getenv("RELAY_ADDRS")))
	if err != nil {
		log.Fatal("bad RELAY_ADDRS: ", err)
	}

	h, err := p2p.NewHost(priv, nil, staticRelays) // no listenAddrs -> pure outbound client
	// Can connect to others, cannot accept incoming connections
	if err != nil {
		log.Fatal("libp2p host creation failed: ", err)
	}
	defer h.Close()

	// bcoz libp2p APIs don't work with plain strings, so just converting into multiaddr.Multiaddr
	maddr, err := multiaddr.NewMultiaddr(targetAddr)
	if err != nil {
		log.Fatal("invalid server multiaddr: ", err)
	}

	// this just parses the maddr, and extracts the information like ip, protocol etc from the maddr
	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		log.Fatal("couldn't extract peer info from multiaddr: ", err)
	}

	// this is just implementing a timeout for the connection to establish, this context will be feeded while creating the new connection
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// this just establishes a conn between the client and the given peerID
	if err := h.Connect(ctx, *info); err != nil {
		log.Fatal("libp2p connection wasnt established : ", err)
	}
	fmt.Println("libp2p connection established with", info.ID)

	// Opening a stream here is the libp2p equivalent of net.DialTCP
	// returning a *net.TCPConn: after this call, s behaves like any
	// other protocol.Stream (io.Reader + io.Writer + io.Closer).

	s, err := h.NewStream(ctx, info.ID, p2p.ProtocolID)
	if err != nil {
		log.Fatal("couldn't open stream: ", err)
	}
	defer s.Close()

	switch method {

	case "POST":
		fmt.Println("Reached POST method in client.go")
		RequestFile(path, s, method)
		fmt.Println("Completed the ReqFile func now starting SendFile in client.go")
		if err := controllers.SendFile(path, s); err != nil {
			log.Println("SendFile failed:", err)
		}

	case "GET":
		fmt.Println("Reached GET method in client.go")
		RequestFile(path, s, method)
		fmt.Println("Completed the ReqFile func now starting RecieveFile in client.go")
		if err := controllers.RecieveFile(s); err != nil {
			log.Println("RecieveFile failed:", err)
		}

	default:
		fmt.Println("Unknown command")
	}
}

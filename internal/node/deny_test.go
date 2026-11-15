package node

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/bitllm-org/bitllm/internal/protocol"
	"github.com/bitllm-org/bitllm/internal/receipts"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// TestDenyAdmit: a denied peer is refused before any slot, quota or allow
// list is consulted, with a message clients treat as permanent; every other
// peer is unaffected.
func TestDenyAdmit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bad, good := randomPeer(t), randomPeer(t)
	n := testNode(t, ctx, Config{Deny: map[peer.ID]bool{bad: true}})
	now := time.Now()

	s, msg, _ := n.admit(bad, "", now, 0, 0)
	if s != 403 || msg != msgDenied || !notAllowed(s, msg) {
		t.Fatalf("denied peer: %d %s", s, msg)
	}
	if n.inflight.Load() != 0 {
		t.Fatalf("slots leaked: %d", n.inflight.Load())
	}
	if got := n.refused.snapshot()["deny"]; got != 1 {
		t.Fatalf("refusals.deny = %d, want 1", got)
	}

	s, msg, a := n.admit(good, "", now, 0, 0)
	if s != 0 {
		t.Fatalf("peer not denied: %d %s", s, msg)
	}
	n.done(a.t, 0, now)
}

// TestDenyBeforeRead: a denied peer is refused before it sends a body, takes
// no reader slot or byte budget, and hears the deny message even when --allow
// would also have refused it.
func TestDenyBeforeRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	key, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := peer.IDFromPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	n := testNode(t, ctx, Config{
		Upstream: "http://127.0.0.1:1/v1", // only registers the infer handler
		Deny:     map[peer.ID]bool{bad: true},
		Allow:    map[peer.ID]bool{randomPeer(t): true}, // --deny wins over the allow list
	})
	h := rawPeer(t, n, key, "")
	for i := 0; i < maxPeerReaders+2; i++ {
		s, err := h.NewStream(ctx, n.host.ID(), protocol.InferProto2)
		if err != nil {
			t.Fatal(err)
		}
		_, hdr := readHdr(t, bufio.NewReader(s), s, 10*time.Second)
		if hdr.Status != 403 || hdr.Error != msgDenied || !notAllowed(hdr.Status, hdr.Error) {
			t.Fatalf("request %d: %d %q", i, hdr.Status, hdr.Error)
		}
		s.Reset()
	}
	if got := n.refused.snapshot(); got["deny"] != int64(maxPeerReaders+2) || got["allow"] != 0 {
		t.Fatalf("refusals = %v", got)
	}
	n.gate.mu.Lock()
	readers, bytes := n.gate.readers, n.gate.bytes
	n.gate.mu.Unlock()
	if readers != 0 || bytes != 0 {
		t.Fatalf("a denied peer held gate state: readers=%d bytes=%d", readers, bytes)
	}
}

// TestPeerBindingLog: the line written when a receipt is countersigned ties
// the receipt pseudonym to the node id that delivered it, which the ledger
// alone cannot do. Nothing is written unless the operator turned it on.
func TestPeerBindingLog(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	off := testNode(t, ctx, Config{})
	off.recordPeerBinding(receipts.SignedReceipt{}, randomPeer(t), "/ip4/1.2.3.4/tcp/4001")
	if _, err := os.Stat(filepath.Join(off.cfg.DataDir, "attribution.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("log written without --attribution-log: %v", err)
	}

	n := testNode(t, ctx, Config{AttributionLog: true})
	from := randomPeer(t)
	sr := receipts.SignedReceipt{Receipt: receipts.Receipt{
		Job: "JOB1", Model: "m", Client: "pseudonym", Server: n.host.ID().String(),
		Prompt: 1000, Completion: 20, Credits: 270, TS: 1700000000,
	}}
	n.recordPeerBinding(sr, from, "/ip4/1.2.3.4/tcp/4001")

	path := filepath.Join(n.cfg.DataDir, "attribution.jsonl")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows has no owner-only mode bits; the file sits in the user's profile there.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Node, Client, Addr, Job string
		Prompt                  int64 `json:"prompt_tokens"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("line is not json: %v", err)
	}
	if got.Node != from.String() || got.Client != "pseudonym" || got.Addr != "/ip4/1.2.3.4/tcp/4001" ||
		got.Job != "JOB1" || got.Prompt != 1000 {
		t.Fatalf("binding = %+v", got)
	}
	// A file left with a wider mode by an older build is tightened.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		n.recordPeerBinding(sr, from, "/ip4/1.2.3.4/tcp/4001")
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode after rewrite = %v", info.Mode().Perm())
		}
	}
}

// TestPeerBindingLogRotates: past the size cap the log moves to .1 and a fresh
// file starts, so a busy host keeps the recent window and one older file.
func TestPeerBindingLogRotates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setVar(t, &attributionLogMax, 1)
	n := testNode(t, ctx, Config{AttributionLog: true})
	from := randomPeer(t)
	n.recordPeerBinding(receipts.SignedReceipt{}, from, "/ip4/1.2.3.4/tcp/4001")
	n.recordPeerBinding(receipts.SignedReceipt{}, from, "/ip4/1.2.3.4/tcp/4001")
	path := filepath.Join(n.cfg.DataDir, "attribution.jsonl")
	for _, p := range []string{path, path + ".1"} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
}

// TestAttributionNeedsCountersignedReceipt: a receipt the node rejects leaves
// no attribution line, because the line is written only after Countersign.
func TestAttributionNeedsCountersignedReceipt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := testNode(t, ctx, Config{AttributionLog: true})
	h := rawPeer(t, n, nil, "")
	s, err := h.NewStream(ctx, n.host.ID(), protocol.ReceiptProto)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Reset()
	if err := json.NewEncoder(s).Encode(receipts.SignedReceipt{}); err != nil {
		t.Fatal(err)
	}
	s.CloseWrite()
	s.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.Copy(io.Discard, s)
	if _, err := os.Stat(filepath.Join(n.cfg.DataDir, "attribution.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("a rejected receipt wrote an attribution line: %v", err)
	}
}

package node

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bitllm-org/bitllm/internal/receipts"
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
	if info.Mode().Perm() != 0o600 {
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
}

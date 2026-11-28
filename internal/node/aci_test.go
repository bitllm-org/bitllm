package node

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bitllm-org/bitllm/internal/aci"
)

const teeModel = "phala/deepseek-v4.1-flash-1017-uncensored"

// teeUpstream stands in for a TEE gateway: it serves a "report" carrying its
// E2EE key, opens sealed requests and seals its answers. seen collects every
// request body it got, to show what the relaying server could read.
func teeUpstream(t *testing.T) (*httptest.Server, *[]string) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	sv := aci.Service{Key: key}
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			fmt.Fprintf(w, `{"data":[{"id":%q}]}`, teeModel)
		case "/v1/aci/attestation":
			json.NewEncoder(w).Encode(map[string]string{"key": fmt.Sprintf("%x", key.PublicKey().Bytes()), "nonce": r.URL.Query().Get("nonce")})
		case "/v1/chat/completions":
			raw, _ := io.ReadAll(r.Body)
			mu.Lock()
			seen = append(seen, string(raw))
			mu.Unlock()
			var body struct {
				Model    string `json:"model"`
				Stream   bool   `json:"stream"`
				Provider struct {
					ACIVerified bool `json:"aci_verified"`
				} `json:"provider"`
				Messages []struct {
					Content string `json:"content"`
				} `json:"messages"`
				Tools []any `json:"tools"`
			}
			json.Unmarshal(raw, &body)
			h := map[string]string{}
			for _, k := range aci.HeaderNames {
				h[k] = r.Header.Get(k)
			}
			s, err := sv.Session(body.Model, h)
			if err != nil || !body.Provider.ACIVerified {
				http.Error(w, `{"error":{"type":"e2ee_header_missing"}}`, 400)
				return
			}
			var said []string
			for i, m := range body.Messages {
				p, err := sv.OpenField(s, fmt.Sprintf("messages.%d.content", i), m.Content)
				if err != nil {
					http.Error(w, `{"error":{"type":"e2ee_decryption_failed"}}`, 400)
					return
				}
				said = append(said, p)
			}
			answer := "you said: " + strings.Join(said, " | ")
			if !body.Stream {
				call := ""
				if len(body.Tools) > 0 {
					// E2EE v2 leaves tool calls readable, as a real gateway does.
					call = `,"tool_calls":[{"id":"t1","type":"function","function":{"name":"lookup","arguments":"{}"}}]`
				}
				fmt.Fprintf(w, `{"id":"r1","choices":[{"index":0,"message":{"role":"assistant","content":%q%s}}],"usage":{"prompt_tokens":5,"completion_tokens":3}}`,
					sv.SealField(s, "r1", "choices.0.message.content", answer), call)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			for i, part := range []string{answer[:5], answer[5:]} {
				_ = i
				fmt.Fprintf(w, "data: {\"id\":\"r1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":%q}}]}\n\n", sv.SealField(s, "r1", "choices.0.delta.content", part))
			}
			fmt.Fprint(w, "data: {\"id\":\"r1\",\"choices\":[],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":3}}\n\ndata: [DONE]\n\n")
		default:
			http.NotFound(w, r)
		}
	}))
	return srv, &seen
}

func TestSealedEndToEnd(t *testing.T) {
	old := verifyReport
	verifyReport = func(raw []byte, nonce string) (*aci.Verified, error) {
		var r struct{ Key, Nonce string }
		json.Unmarshal(raw, &r)
		if r.Nonce != nonce {
			return nil, fmt.Errorf("stale report")
		}
		var k []byte
		fmt.Sscanf(r.Key, "%x", &k)
		return &aci.Verified{Key: k, NotAfter: time.Now().Add(time.Hour), RepoCommit: "abc123", TCB: "up-to-date"}, nil
	}
	t.Cleanup(func() { verifyReport = old })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	up, seen := teeUpstream(t)
	defer up.Close()
	boot := testNode(t, ctx, Config{})
	bs := boot.Addrs()[:1]
	server := testNode(t, ctx, Config{Bootstrap: bs, Upstream: up.URL + "/v1", E2EEOnly: true,
		Models: map[string]string{teeModel: teeModel}})
	client := testNode(t, ctx, Config{Bootstrap: bs})
	deadline := time.Now().Add(20 * time.Second)
	for len(client.candidates(teeModel)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("client never discovered the server's model")
		}
		time.Sleep(100 * time.Millisecond)
	}

	for _, stream := range []bool{false, true} {
		w := post(client, fmt.Sprintf(`{"model":%q,"stream":%v,"messages":[{"role":"system","content":"secret-sys"},{"role":"user","content":"secret-question"}]}`, teeModel, stream))
		if w.Code != 200 {
			t.Fatalf("stream=%v: %d %s", stream, w.Code, w.Body)
		}
		if h := w.Header().Get("X-BitLLM-TEE"); !strings.HasPrefix(h, "verified;") || !strings.Contains(h, "build=abc123") || !strings.Contains(h, "tcb=up-to-date") || strings.Contains(h, "tools=") {
			t.Fatalf("stream=%v: X-BitLLM-TEE %q", stream, h)
		}
		out := w.Body.String()
		if stream {
			var text strings.Builder
			for _, l := range strings.Split(out, "\n") {
				var c struct {
					Choices []struct {
						Delta struct{ Content string }
					}
				}
				if json.Unmarshal([]byte(strings.TrimPrefix(l, "data: ")), &c) == nil && len(c.Choices) > 0 {
					text.WriteString(c.Choices[0].Delta.Content)
				}
			}
			out = text.String()
		}
		if !strings.Contains(out, "you said: secret-sys | secret-question") {
			t.Fatalf("stream=%v: answer %q", stream, w.Body)
		}
	}
	// GET /status shows the TEE this client verified.
	if tee, _ := client.teeStatus()[teeModel].(map[string]any); tee == nil || tee["build"] != "abc123" {
		t.Fatalf("status tee: %v", client.teeStatus())
	}
	// What crossed the relaying server was sealed.
	for _, b := range *seen {
		if strings.Contains(b, "secret") {
			t.Fatalf("the server saw plaintext: %s", b)
		}
	}
	if len(*seen) != 2 {
		t.Fatalf("upstream got %d requests", len(*seen))
	}

	// A request in the clear, from a client that does not seal, is refused.
	_, _, err := func() (int, string, error) {
		w := httptest.NewRecorder()
		_, err := client.infer(ctx, server.host.ID(), "/chat/completions",
			[]byte(fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"plain"}]}`, teeModel)), false, w, 0)
		return 0, "", err
	}()
	if err == nil || !strings.Contains(err.Error(), "sealed") {
		t.Fatalf("plain request: %v", err)
	}
	if len(*seen) != 2 {
		t.Fatal("a plain request reached the TEE upstream")
	}

	// Tool definitions and tool calls are not sealed (E2EE v2): the answer's
	// tool call passes unchecked, and the header says tools went readable.
	w := post(client, fmt.Sprintf(`{"model":%q,"tools":[{"type":"function","function":{"name":"lookup"}}],"messages":[{"role":"user","content":"find a.txt"}]}`, teeModel))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"lookup"`) {
		t.Fatalf("tools offered: %d %s", w.Code, w.Body)
	}
	if h := w.Header().Get("X-BitLLM-TEE"); !strings.HasSuffix(h, "; tools=unsealed") {
		t.Fatalf("tools offered: X-BitLLM-TEE %q", h)
	}
}

// TestNewNodeQuota: a node first seen today gets --new-daily, and with
// --open-daily-hard a spent pool refuses rather than serving when idle.
func TestNewNodeQuota(t *testing.T) {
	ctx := t.Context()
	root := newEthKey(t)
	n := testNode(t, ctx, Config{Roots: []string{root.addr}, Open: true, OpenSlots: 2, OpenDaily: 100,
		FreeDaily: 50, NewDaily: 10, OpenDailyHard: true, QuotaNote: "Buy more at example.org", Concurrency: 3})
	now := time.Now()
	fresh, old := randomPeer(t), randomPeer(t)
	n.seen.at[old.String()] = now.Add(-48 * time.Hour).Unix()

	s, _, a := n.admit(fresh, "", now, 0, 0)
	if s != 0 || a.t.limit != 10 {
		t.Fatalf("new node: %d limit=%d, want the new-node quota 10", s, a.t.limit)
	}
	n.done(a.t, 10, now)
	if s, msg, _ := n.admit(fresh, "", now, 0, 0); s != 429 || !strings.Contains(msg, "example.org") {
		t.Fatalf("spent new node: %d %s", s, msg)
	}
	s, _, a = n.admit(old, "", now, 0, 0)
	if s != 0 || a.t.limit != 50 {
		t.Fatalf("old node: %d limit=%d, want 50", s, a.t.limit)
	}
	n.done(a.t, 50, now)
	// A day later the fresh node is no longer new.
	later := now.Add(25 * time.Hour)
	if !n.seen.isNew(randomPeer(t), later) || n.seen.isNew(fresh, later) {
		t.Fatal("first-seen age is wrong")
	}

	// Spend the pool (100): 10 + 50 used, 40 left.
	third := randomPeer(t)
	n.seen.at[third.String()] = now.Add(-48 * time.Hour).Unix()
	s, _, a = n.admit(third, "", now, 0, 40)
	if s != 0 {
		t.Fatalf("third: %d", s)
	}
	n.done(a.t, 40, now)
	fourth := randomPeer(t)
	if s, msg, _ := n.admit(fourth, "", now, 0, 0); s != 429 || msg != n.quotaMsg(msgPoolSpent) {
		t.Fatalf("spent pool: %d %s", s, msg)
	}
}

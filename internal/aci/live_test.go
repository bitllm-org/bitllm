//go:build live

// Live checks against tee.redpill.ai: go test -tags live ./internal/aci/
// With REDPILL_KEY set it also sends one sealed chat request.
package aci

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const liveBase = "https://tee.redpill.ai/v1"

func liveVerify(t *testing.T) *Verified {
	n := make([]byte, 32)
	rand.Read(n)
	nonce := hex.EncodeToString(n)
	resp, err := http.Get(liveBase + "/aci/attestation?nonce=" + nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, MaxReport))
	v, err := Verify(raw, nonce, time.Now(), DefaultPolicy)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("verified: commit %s compose %s keyset %s until %s", v.RepoCommit, v.ComposeHash, v.Digest, v.NotAfter)
	st, err := CheckTCB(raw, time.Now(), nil)
	if err != nil || st != TCBUpToDate {
		t.Fatalf("TCB: %q, %v", st, err)
	}
	return v
}

func TestLiveAttestation(t *testing.T) { liveVerify(t) }

func TestLiveSealedChat(t *testing.T) {
	key := os.Getenv("REDPILL_KEY")
	if key == "" {
		t.Skip("REDPILL_KEY not set")
	}
	model := os.Getenv("REDPILL_MODEL")
	if model == "" {
		model = "phala/deepseek-v4.1-flash-1017-uncensored"
	}
	v := liveVerify(t)
	for _, stream := range []bool{false, true} {
		s, err := NewSession(v, model, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		body := map[string]any{"model": model, "stream": stream, "max_tokens": 40,
			"provider": map[string]any{"aci_verified": true},
			"messages": []any{map[string]any{"role": "user", "content": "Reply with exactly: sealed ok"}}}
		if err := s.SealChat(body); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", liveBase+"/chat/completions", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+key)
		for k, v := range s.Headers() {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			msg, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("stream=%v: %d %s", stream, resp.StatusCode, msg)
		}
		var text strings.Builder
		if !stream {
			raw, _ := io.ReadAll(resp.Body)
			out, err := s.OpenBody(raw)
			if err != nil {
				t.Fatalf("open: %v\n%s", err, raw)
			}
			text.Write(out)
		} else {
			r := bufio.NewReader(resp.Body)
			for {
				line, err := r.ReadBytes('\n')
				if len(line) > 0 {
					out, oerr := s.OpenSSELine(line)
					if oerr != nil {
						t.Fatalf("open line: %v\n%s", oerr, line)
					}
					text.Write(out)
				}
				if err != nil {
					break
				}
			}
		}
		resp.Body.Close()
		t.Logf("stream=%v e2ee-applied=%s answer:\n%s", stream, resp.Header.Get("X-E2EE-Applied"), text.String())
		if !strings.Contains(strings.ToLower(text.String()), "sealed") {
			t.Fatalf("stream=%v: unexpected answer", stream)
		}
	}
}

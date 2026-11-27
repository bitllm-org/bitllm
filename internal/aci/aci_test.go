package aci

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The AAD bytes from spec/e2ee-v2-test-vectors.md.
func TestAADVectors(t *testing.T) {
	s := &Session{model: "demo-model", nonce: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", ts: 1750000000}
	req := `{"algo":"x25519-aes-256-gcm-hkdf-sha256","field":"messages.0.content","model":"demo-model","nonce":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","purpose":"aci.e2ee.request.v2","ts":1750000000}`
	if got := string(s.aad("aci.e2ee.request.v2", "", "messages.0.content")); got != req {
		t.Fatalf("request aad\n got %s\nwant %s", got, req)
	}
	resp := `{"algo":"x25519-aes-256-gcm-hkdf-sha256","field":"choices.0.message.content","id":"chatcmpl-123","model":"demo-model","nonce":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","purpose":"aci.e2ee.response.v2","ts":1750000000}`
	if got := string(s.aad("aci.e2ee.response.v2", "chatcmpl-123", "choices.0.message.content")); got != resp {
		t.Fatalf("response aad\n got %s\nwant %s", got, resp)
	}
	// The vector's service key, from a seed of 32 x 0x03.
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 3
	}
	k, _ := ecdh.X25519().NewPrivateKey(seed)
	if hex.EncodeToString(k.PublicKey().Bytes()) != "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22" {
		t.Fatal("x25519 public key differs from the vector")
	}
}

func loadReport(t *testing.T) ([]byte, string, time.Time) {
	raw, err := os.ReadFile("testdata/redpill-attestation.json")
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := os.ReadFile("testdata/redpill-attestation.nonce")
	ts, _ := os.ReadFile("testdata/redpill-attestation.time")
	sec, _ := strconv.ParseInt(strings.TrimSpace(string(ts)), 10, 64)
	return raw, strings.TrimSpace(string(nonce)), time.Unix(sec, 0)
}

func TestVerifyLiveReport(t *testing.T) {
	raw, nonce, at := loadReport(t)
	v, err := Verify(raw, nonce, at, DefaultPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Key) != 32 || v.ComposeHash == "" {
		t.Fatalf("verified %+v", v)
	}

	// Another nonce: a replayed report.
	other := strings.Repeat("ab", 32)
	if _, err := Verify(raw, other, at, DefaultPolicy); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("replayed report: %v", err)
	}
	// A build we do not accept.
	if _, err := Verify(raw, nonce, at, Policy{}); err == nil || !strings.Contains(err.Error(), "accepted list") {
		t.Fatalf("empty policy: %v", err)
	}
	// After expiry.
	if _, err := Verify(raw, nonce, v.NotAfter.Add(time.Second), DefaultPolicy); err == nil {
		t.Fatal("expired keyset accepted")
	}
	// A swapped E2EE key breaks the keyset digest.
	var doc map[string]any
	json.Unmarshal(raw, &doc)
	ks := doc["attestation"].(map[string]any)["workload_keyset"].(map[string]any)
	keys := ks["e2ee_public_keys"].([]any)
	keys[len(keys)-1].(map[string]any)["public_key"] = strings.Repeat("11", 32)
	bad, _ := json.Marshal(doc)
	if _, err := Verify(bad, nonce, at, DefaultPolicy); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("swapped key: %v", err)
	}
	// A different compose than the one measured.
	json.Unmarshal(raw, &doc)
	doc["attestation"].(map[string]any)["evidence"].(map[string]any)["app_compose"] = "{}"
	bad, _ = json.Marshal(doc)
	if _, err := Verify(bad, nonce, at, DefaultPolicy); err == nil || !strings.Contains(err.Error(), "compose") {
		t.Fatalf("swapped compose: %v", err)
	}
}

// service plays the TEE side: it opens a sealed request field and seals an
// answer field the way spec/e2ee-v2.md describes.
type service struct{ key *ecdh.PrivateKey }

func (sv service) open(t *testing.T, s *Session, field, ct string) string {
	b, _ := hex.DecodeString(ct)
	eph, _ := ecdh.X25519().NewPublicKey(b[:32])
	shared, _ := sv.key.ECDH(eph)
	a, _ := gcm(shared)
	plain, err := a.Open(nil, b[32:44], b[44:], s.aad("aci.e2ee.request.v2", "", field))
	if err != nil {
		t.Fatalf("service cannot open %s: %v", field, err)
	}
	return string(plain)
}

func (sv service) seal(s *Session, id, field, plain string) string {
	clientPub, _ := hex.DecodeString(s.Headers()["X-Client-Pub-Key"])
	cp, _ := ecdh.X25519().NewPublicKey(clientPub)
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	shared, _ := eph.ECDH(cp)
	a, _ := gcm(shared)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	out := append(eph.PublicKey().Bytes(), nonce...)
	return hex.EncodeToString(a.Seal(out, nonce, []byte(plain), s.aad("aci.e2ee.response.v2", id, field)))
}

func TestSealOpenRoundTrip(t *testing.T) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	sv := service{key}
	s, err := NewSession(&Verified{Key: key.PublicKey().Bytes()}, "m", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"model": "m", "messages": []any{
		map[string]any{"role": "system", "content": "be brief"},
		map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": "hi <b>"}}},
	}}
	if err := s.SealChat(body); err != nil {
		t.Fatal(err)
	}
	msgs := body["messages"].([]any)
	if got := sv.open(t, s, "messages.0.content", msgs[0].(map[string]any)["content"].(string)); got != "be brief" {
		t.Fatalf("got %q", got)
	}
	if got := sv.open(t, s, "messages.1.content", msgs[1].(map[string]any)["content"].(string)); got != `[{"text":"hi <b>","type":"text"}]` {
		t.Fatalf("got %q", got)
	}

	// A streamed chunk with the choice index taken from the choice.
	chunk := `{"id":"c1","choices":[{"index":0,"delta":{"content":"` + sv.seal(s, "c1", "choices.0.delta.content", "hello") + `"}}],"usage":null}`
	line, err := s.OpenSSELine([]byte("data: " + chunk + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(line), `"content":"hello"`) || !strings.HasSuffix(string(line), "\n") {
		t.Fatalf("line %q", line)
	}
	if l, _ := s.OpenSSELine([]byte("data: [DONE]\n")); string(l) != "data: [DONE]\n" {
		t.Fatalf("done line %q", l)
	}
	// A plain answer where a sealed one was due is refused.
	if _, err := s.OpenSSELine([]byte(`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"plain"}}]}` + "\n")); err == nil {
		t.Fatal("plain content accepted")
	}
	// Ciphertext moved to another field does not open.
	moved := `{"id":"c1","choices":[{"index":0,"message":{"content":"` + sv.seal(s, "c1", "choices.0.message.reasoning_content", "x") + `"}}]}`
	if _, err := s.OpenBody([]byte(moved)); err == nil {
		t.Fatal("moved ciphertext opened")
	}
	ok := `{"id":"c1","choices":[{"index":0,"message":{"role":"assistant","content":"` + sv.seal(s, "c1", "choices.0.message.content", "fine") + `"}}],"usage":{"prompt_tokens":3}}`
	out, err := s.OpenBody([]byte(ok))
	if err != nil || !strings.Contains(string(out), `"content":"fine"`) || !strings.Contains(string(out), `"prompt_tokens":3`) {
		t.Fatalf("body %s %v", out, err)
	}
}

type downGetter struct{}

func (downGetter) Get(string) (map[string][]string, []byte, error) {
	return nil, nil, errors.New("no route to host")
}

// TestCheckTCBUnreachable: with Intel's PCS out of reach the check fails open
// and says so, rather than taking the model down.
func TestCheckTCBUnreachable(t *testing.T) {
	raw, _, at := loadReport(t)
	st, err := CheckTCB(raw, at, downGetter{})
	if err != nil || st != TCBUnchecked {
		t.Fatalf("got %q, %v", st, err)
	}
	if _, err := CheckTCB([]byte(`{}`), at, downGetter{}); err == nil {
		t.Fatal("a report with no quote passed")
	}
}

package node

import (
	"bufio"
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/bitllm-org/bitllm/internal/aci"
	"github.com/bitllm-org/bitllm/internal/protocol"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	p2pproto "github.com/libp2p/go-libp2p/core/protocol"
)

const msgSealedOnly = "this server takes only chat requests sealed to its TEE (end-to-end encrypted); update bitllm to use it"

// sealedHeaders keeps the E2EE v2 headers of a peer's request, and returns
// nil unless all five are there and look right.
func sealedHeaders(h map[string]string) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(aci.HeaderNames))
	for _, k := range aci.HeaderNames {
		v, ok := h[k]
		if !ok || !aci.ValidHeaderValue(k, v) {
			return nil
		}
		out[k] = v
	}
	return out
}

// aciGap spaces the attestation reports this server fetches for peers: each
// one makes the TEE produce a hardware quote.
const aciGap = 200 * time.Millisecond

// handleACI fetches a fresh attestation report from our upstream for a peer's
// nonce. The report is public, and the nonce makes it unusable for anyone else.
func (n *Node) handleACI(s network.Stream) {
	defer s.Close()
	remote := s.Conn().RemotePeer()
	reply := func(status int, msg string) {
		b, _ := json.Marshal(inferHdr{Status: status, Error: msg})
		s.Write(append(b, '\n'))
	}
	if n.cfg.Deny[remote] {
		reply(403, msgDenied)
		return
	}
	s.SetReadDeadline(time.Now().Add(readTimeout))
	line, err := bufio.NewReaderSize(io.LimitReader(s, 512), 512).ReadSlice('\n')
	s.SetReadDeadline(time.Time{})
	var req struct {
		Nonce string `json:"nonce"`
	}
	if err != nil || json.Unmarshal(line, &req) != nil || !lowerHex64(req.Nonce) {
		reply(400, "bad request")
		return
	}
	n.aciMu.Lock()
	wait := time.Until(n.aciLast.Add(aciGap))
	if wait > time.Second {
		n.aciMu.Unlock()
		reply(429, msgBusy)
		return
	}
	n.aciLast = time.Now().Add(max(wait, 0))
	n.aciMu.Unlock()
	time.Sleep(max(wait, 0))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	hr, _ := http.NewRequestWithContext(ctx, "GET", n.cfg.Upstream+"/aci/attestation?nonce="+req.Nonce, nil)
	n.upstreamAuth(hr)
	resp, err := n.http.Do(hr)
	if err != nil {
		reply(502, msgUpstream)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, aci.MaxReport+1))
	if err != nil || resp.StatusCode != 200 || len(body) > aci.MaxReport {
		reply(502, msgUpstream)
		return
	}
	reply(200, "")
	s.Write(body)
}

func lowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// attest asks peer p for a fresh report on our nonce and verifies it.
func (n *Node) attest(ctx context.Context, p peer.ID, model string) (*aci.Verified, error) {
	n.addRelayPaths(p)
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	s, err := n.host.NewStream(network.WithAllowLimitedConn(ctx, "aci"), p, p2pproto.ID(protocol.ACIProto))
	if err != nil {
		return nil, err
	}
	defer s.Close()
	stop := context.AfterFunc(ctx, func() { s.Reset() })
	defer stop()
	nonce := randomHex32()
	b, _ := json.Marshal(map[string]string{"nonce": nonce})
	if _, err := s.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	s.CloseWrite()
	r := bufio.NewReaderSize(io.LimitReader(s, aci.MaxReport+4096), 4096)
	line, err := r.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	var hdr inferHdr
	if err := json.Unmarshal(line, &hdr); err != nil {
		return nil, err
	}
	if hdr.Status != 200 {
		return nil, &peerError{hdr.Status, cleanPeerText(hdr.Error, maxPeerText)}
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return verifyReport(raw, nonce)
}

// verifyReport checks a report; tests swap it, having no TDX hardware.
var verifyReport = func(raw []byte, nonce string) (*aci.Verified, error) {
	now := time.Now()
	v, err := aci.Verify(raw, nonce, now, aci.DefaultPolicy)
	if err != nil {
		return nil, err
	}
	if v.TCB, err = aci.CheckTCB(raw, now, nil); err != nil {
		return nil, err
	}
	return v, nil
}

// teeRecheck is how long a verified TEE key is used before a fresh report.
const teeRecheck = time.Hour

type teeKey struct {
	v    *aci.Verified
	when time.Time
}

// teeKeyFor returns a verified TEE key for model, from cache or from a fresh
// report through one of the peers that serve it.
func (n *Node) teeKeyFor(ctx context.Context, model string, cands []peer.ID) (*aci.Verified, error) {
	n.aciMu.Lock()
	k, ok := n.teeKeys[model]
	n.aciMu.Unlock()
	now := time.Now()
	if ok && now.Before(k.v.NotAfter) && now.Sub(k.when) < teeRecheck {
		return k.v, nil
	}
	var last error = errors.New("no server for this model answered with a TEE report")
	for i, p := range cands {
		if i == 3 {
			break
		}
		v, err := n.attest(ctx, p, model)
		if err != nil {
			log.Printf("TEE report for %s via %s: %v", model, p, err)
			last = err
			continue
		}
		n.aciMu.Lock()
		if n.teeKeys == nil {
			n.teeKeys = map[string]teeKey{}
		}
		n.teeKeys[model] = teeKey{v, now}
		n.aciMu.Unlock()
		log.Printf("verified the TEE behind %s: build %s, keyset %.24s…, Intel TCB %s, valid until %s", model, v.RepoCommit, v.Digest, tcbOr(v.TCB), v.NotAfter.Format(time.DateOnly))
		return v, nil
	}
	return nil, last
}

// teeSummary is the X-BitLLM-TEE value for an answer sealed to v.
func teeSummary(v *aci.Verified) string {
	return fmt.Sprintf("verified; e2ee=v2; tcb=%s; build=%s; compose=%s; keyset=%s; valid_until=%s",
		tcbOr(v.TCB), v.RepoCommit, v.ComposeHash, v.Digest, v.NotAfter.UTC().Format(time.RFC3339))
}

func tcbOr(s string) string {
	if s == "" {
		return aci.TCBUnchecked
	}
	return s
}

// teeStatus lists, per end-to-end encrypted model, the TEE this client last
// verified, for GET /status.
func (n *Node) teeStatus() map[string]any {
	n.aciMu.Lock()
	defer n.aciMu.Unlock()
	out := map[string]any{}
	for model, k := range n.teeKeys {
		out[model] = map[string]any{
			"verified":    true,
			"checked_at":  k.when.UTC().Format(time.RFC3339),
			"build":       k.v.RepoCommit,
			"compose":     k.v.ComposeHash,
			"keyset":      k.v.Digest,
			"valid_until": k.v.NotAfter.UTC().Format(time.RFC3339),
			"e2ee":        "v2",
			"tcb":         tcbOr(k.v.TCB),
		}
	}
	return out
}

// sealRequest seals a chat request body for model and returns it with the
// session that opens the answer.
func sealRequest(v *aci.Verified, model string, body []byte) ([]byte, *aci.Session, error) {
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var doc map[string]any
	if err := d.Decode(&doc); err != nil {
		return nil, nil, err
	}
	sess, err := aci.NewSession(v, model, time.Now())
	if err != nil {
		return nil, nil, err
	}
	if err := sess.SealChat(doc); err != nil {
		return nil, nil, err
	}
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(doc); err != nil {
		return nil, nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), sess, nil
}

// openWriter opens a sealed answer on its way to the local client. A field
// that does not open stops the answer: err says why.
type openWriter struct {
	http.ResponseWriter
	sess   *aci.Session
	stream bool
	buf    []byte
	err    error
}

func (o *openWriter) Write(b []byte) (int, error) {
	if o.err != nil {
		return 0, o.err
	}
	if !o.stream {
		// pipePeer writes a buffered answer once, whole.
		out, err := o.sess.OpenBody(b)
		if err != nil {
			o.err = err
			return 0, err
		}
		if _, err := o.ResponseWriter.Write(out); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	o.buf = append(o.buf, b...)
	for {
		i := bytes.IndexByte(o.buf, '\n')
		if i < 0 {
			break
		}
		out, err := o.sess.OpenSSELine(o.buf[:i+1])
		if err != nil {
			o.err = err
			return 0, err
		}
		if _, err := o.ResponseWriter.Write(out); err != nil {
			return 0, err
		}
		o.buf = o.buf[i+1:]
	}
	return len(b), nil
}

func (o *openWriter) Flush() {
	if f, ok := o.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// sealedFor reports whether requests for model must be sealed to a TEE.
func sealedFor(model string) bool { return teeModels[model] }

// What GET /v1/models says about who can read a model's requests, so nobody
// mistakes one kind for the other.
const (
	// The gateway seals every request to a TEE it verified; no relay or
	// operator can read it.
	privacyTEE = "tee-e2ee"
	// The node that serves the model reads the request, like any API
	// provider: you trust its operator.
	privacyOperator = "operator-trusted"
)

func privacyOf(model string) string {
	if sealedFor(model) {
		return privacyTEE
	}
	return privacyOperator
}

// teeModels are served behind Attested Confidential Inference: the gateway
// seals every request for them and refuses to send one in the clear.
var teeModels = map[string]bool{
	"phala/deepseek-v4.1-flash-1017-uncensored": true,
}

func teeErr(err error) string {
	return fmt.Sprintf("could not verify the TEE that serves this model, so nothing was sent: %v", err)
}

func randomHex32() string {
	b := make([]byte, 32)
	crand.Read(b)
	return hex.EncodeToString(b)
}

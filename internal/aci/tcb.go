package aci

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"
)

// What CheckTCB can report about a platform's TCB.
const (
	TCBUpToDate  = "up-to-date" // Intel's collateral says the platform is patched and not revoked
	TCBUnchecked = "unchecked"  // Intel's collateral service could not be reached
)

// CheckTCB asks Intel's collateral service (PCS) whether the platform behind
// a report Verify already accepted is up to date and its certificates are not
// revoked. Verify alone proves the quote chains to Intel's root but not that
// the platform has the current microcode and TDX module.
//
// It fails closed on what Intel says: any status other than UpToDate, or a
// revoked certificate, is an error. It fails open when Intel cannot be
// reached, returning TCBUnchecked, so an outage at Intel does not take the
// model down; callers show that status to the user. getter nil means the
// network.
func CheckTCB(raw []byte, now time.Time, getter trust.HTTPSGetter) (string, error) {
	var r Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", fmt.Errorf("aci: bad report: %w", err)
	}
	qb, err := hex.DecodeString(r.Attestation.Evidence.Quote)
	if err != nil {
		return "", fmt.Errorf("aci: quote is not hex")
	}
	qa, err := abi.QuoteToProto(qb)
	if err != nil {
		return "", fmt.Errorf("aci: bad quote: %w", err)
	}
	q, ok := qa.(*pb.QuoteV4)
	if !ok {
		return "", fmt.Errorf("aci: quote type %T, want TDX v4", qa)
	}
	if getter == nil {
		getter = pcsGetter{&http.Client{Timeout: 10 * time.Second}}
	}
	g := &watchGetter{inner: getter}
	opts := verify.DefaultOptions()
	opts.Now = now
	opts.GetCollateral = true
	opts.CheckRevocations = true
	opts.Getter = g
	err = verify.TdxQuote(q, opts)
	if g.failed.Load() {
		return TCBUnchecked, nil
	}
	if err != nil {
		return "", fmt.Errorf("aci: Intel does not vouch for this platform's TCB: %w", err)
	}
	return TCBUpToDate, nil
}

// watchGetter notes whether any fetch failed, which is how CheckTCB tells
// "Intel unreachable" from "Intel says no".
type watchGetter struct {
	inner  trust.HTTPSGetter
	failed atomic.Bool
}

func (w *watchGetter) Get(url string) (map[string][]string, []byte, error) {
	h, b, err := w.inner.Get(url)
	if err != nil {
		w.failed.Store(true)
	}
	return h, b, err
}

// pcsGetter is one attempt with a timeout: the library's default getter
// retries for minutes, and a request is waiting on this.
type pcsGetter struct{ c *http.Client }

func (p pcsGetter) Get(url string) (map[string][]string, []byte, error) {
	resp, err := p.c.Get(url)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.Header, b, err
}

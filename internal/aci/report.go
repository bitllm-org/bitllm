package aci

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
)

// MaxReport bounds an attestation report. A live one is about 60 KB.
const MaxReport = 512 << 10

// Report is the part of an ACI attestation report (spec/aci.md §4.1) that the
// checks below read.
type Report struct {
	APIVersion           string `json:"api_version"`
	WorkloadKeysetDigest string `json:"workload_keyset_digest"`
	Attestation          struct {
		TeeType        string          `json:"tee_type"`
		WorkloadKeyset json.RawMessage `json:"workload_keyset"`
		ReportData     string          `json:"report_data"`
		Source         struct {
			RepoURL    string `json:"repo_url"`
			RepoCommit string `json:"repo_commit"`
		} `json:"source_provenance"`
		Evidence struct {
			Quote      string `json:"quote"`
			EventLog   string `json:"event_log"`
			AppCompose string `json:"app_compose"`
		} `json:"evidence"`
	} `json:"attestation"`
	Capabilities struct {
		E2EEVersions []string `json:"supported_e2ee_versions"`
	} `json:"service_capabilities"`
}

type keyset struct {
	NotAfter int64 `json:"not_after"`
	E2EE     []struct {
		KeyID     string `json:"key_id"`
		Algo      string `json:"algo"`
		PublicKey string `json:"public_key"`
	} `json:"e2ee_public_keys"`
}

// Verified is what a report proved: the TEE that holds Key, until NotAfter.
type Verified struct {
	Digest      string    // workload keyset digest
	NotAfter    time.Time // keyset expiry
	Key         []byte    // X25519 E2EE public key of the workload
	ComposeHash string    // measured sha256 of the app compose
	RepoCommit  string    // source commit the service names
	TCB         string    // TCBUpToDate or TCBUnchecked once CheckTCB ran, else empty
}

// Measurements are one accepted TEE build: the dstack OS image (MRTD, RTMR1,
// RTMR2) and the application compose measured into RTMR3. RTMR0 carries the
// VM's CPU and memory layout, which differ between replicas, so it is not
// pinned.
type Measurements struct {
	Name        string // for error messages
	MRTD        string
	RTMR1       string
	RTMR2       string
	ComposeHash string
}

// Policy lists the builds a client accepts. Empty accepts nothing.
type Policy struct {
	Accept []Measurements
}

// Verify checks a report fetched with nonce against the TEE vendor root, the
// event log, the policy, and the keyset binding (spec/aci.md §9.1, checks 1-4
// and 6; key custody is not checked). It returns the X25519 E2EE key to seal
// requests to.
func Verify(raw []byte, nonce string, now time.Time, pol Policy) (*Verified, error) {
	var r Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("aci: bad report: %w", err)
	}
	if r.APIVersion != "aci/1" {
		return nil, fmt.Errorf("aci: api_version %q, want aci/1", r.APIVersion)
	}
	if r.Attestation.TeeType != "tdx" {
		return nil, fmt.Errorf("aci: tee_type %q, want tdx", r.Attestation.TeeType)
	}

	// Binding and freshness: the keyset hashes to the digest, and the digest
	// with our nonce hashes to the report data.
	d := json.NewDecoder(bytes.NewReader(r.Attestation.WorkloadKeyset))
	d.UseNumber()
	var ksAny any
	if err := d.Decode(&ksAny); err != nil {
		return nil, fmt.Errorf("aci: bad keyset: %w", err)
	}
	jcs, err := canonical(ksAny)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(jcs)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if digest != r.WorkloadKeysetDigest {
		return nil, errors.New("aci: keyset does not match its digest")
	}
	statement := `{"keyset_digest":"` + digest + `","nonce":"` + nonce + `","purpose":"aci.report_data.v1"}`
	rd := sha256.Sum256([]byte(statement))
	if hex.EncodeToString(rd[:]) != r.Attestation.ReportData {
		return nil, errors.New("aci: report data does not bind this keyset and nonce")
	}

	// Hardware: the quote verifies to Intel's root and carries that report data.
	qb, err := hex.DecodeString(r.Attestation.Evidence.Quote)
	if err != nil {
		return nil, errors.New("aci: quote is not hex")
	}
	qa, err := abi.QuoteToProto(qb)
	if err != nil {
		return nil, fmt.Errorf("aci: bad quote: %w", err)
	}
	q, ok := qa.(*pb.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("aci: quote type %T, want TDX v4", qa)
	}
	opts := verify.DefaultOptions()
	opts.Now = now
	if err := verify.TdxQuote(q, opts); err != nil {
		return nil, fmt.Errorf("aci: quote does not verify: %w", err)
	}
	body := q.GetTdQuoteBody()
	want := make([]byte, 64)
	copy(want, rd[:])
	if !bytes.Equal(body.GetReportData(), want) {
		return nil, errors.New("aci: quote does not carry the report data")
	}

	// Measured workload: replay the event log into RTMR3 and read the
	// compose hash it recorded.
	rtmrs := body.GetRtmrs()
	if len(rtmrs) != 4 {
		return nil, errors.New("aci: quote has no RTMRs")
	}
	compose, err := replayRTMR3(r.Attestation.Evidence.EventLog, rtmrs[3])
	if err != nil {
		return nil, err
	}
	cs := sha256.Sum256([]byte(r.Attestation.Evidence.AppCompose))
	if hex.EncodeToString(cs[:]) != compose {
		return nil, errors.New("aci: app compose does not match its measured hash")
	}
	got := Measurements{
		MRTD:        hex.EncodeToString(body.GetMrTd()),
		RTMR1:       hex.EncodeToString(rtmrs[1]),
		RTMR2:       hex.EncodeToString(rtmrs[2]),
		ComposeHash: compose,
	}
	if !pol.accepts(got) {
		return nil, fmt.Errorf("aci: TEE build not on the accepted list (compose %s, mrtd %.16s…); update bitllm", compose, got.MRTD)
	}

	// Expiry and the E2EE key.
	var ks keyset
	if err := json.Unmarshal(r.Attestation.WorkloadKeyset, &ks); err != nil {
		return nil, fmt.Errorf("aci: bad keyset: %w", err)
	}
	notAfter := time.Unix(ks.NotAfter, 0)
	if !now.Before(notAfter) {
		return nil, errors.New("aci: keyset expired")
	}
	if notAfter.After(now.Add(400 * 24 * time.Hour)) {
		return nil, errors.New("aci: keyset expiry implausibly far")
	}
	v2 := false
	for _, v := range r.Capabilities.E2EEVersions {
		v2 = v2 || v == "2"
	}
	if !v2 {
		return nil, errors.New("aci: service does not offer E2EE v2")
	}
	for _, k := range ks.E2EE {
		if k.Algo != AlgoX25519 {
			continue
		}
		key, err := hex.DecodeString(trim0x(k.PublicKey))
		if err != nil || len(key) != 32 {
			return nil, errors.New("aci: bad X25519 key in keyset")
		}
		return &Verified{Digest: digest, NotAfter: notAfter, Key: key, ComposeHash: compose,
			RepoCommit: r.Attestation.Source.RepoCommit}, nil
	}
	return nil, errors.New("aci: keyset has no X25519 E2EE key")
}

func (p Policy) accepts(m Measurements) bool {
	for _, a := range p.Accept {
		if a.MRTD == m.MRTD && a.RTMR1 == m.RTMR1 && a.RTMR2 == m.RTMR2 && a.ComposeHash == m.ComposeHash {
			return true
		}
	}
	return false
}

// replayRTMR3 extends the IMR 3 events of a dstack event log, checks each
// event's digest and the result against the quote, and returns the payload of
// the compose-hash event.
func replayRTMR3(log string, want []byte) (string, error) {
	var events []struct {
		IMR     int    `json:"imr"`
		Type    uint32 `json:"event_type"`
		Digest  string `json:"digest"`
		Event   string `json:"event"`
		Payload string `json:"event_payload"`
	}
	if err := json.Unmarshal([]byte(log), &events); err != nil {
		return "", fmt.Errorf("aci: bad event log: %w", err)
	}
	rtmr := make([]byte, 48)
	compose := ""
	for _, e := range events {
		if e.IMR != 3 {
			continue
		}
		payload, err := hex.DecodeString(e.Payload)
		if err != nil {
			return "", errors.New("aci: event payload is not hex")
		}
		h := sha512.New384()
		binary.Write(h, binary.LittleEndian, e.Type)
		h.Write([]byte(":" + e.Event + ":"))
		h.Write(payload)
		dg := h.Sum(nil)
		if hex.EncodeToString(dg) != e.Digest {
			return "", fmt.Errorf("aci: event %q digest does not match its content", e.Event)
		}
		ext := sha512.Sum384(append(rtmr, dg...))
		rtmr = ext[:]
		if e.Event == "compose-hash" {
			if compose != "" {
				return "", errors.New("aci: two compose-hash events")
			}
			compose = hex.EncodeToString(payload)
		}
	}
	if !bytes.Equal(rtmr, want) {
		return "", errors.New("aci: event log does not replay to RTMR3")
	}
	if compose == "" {
		return "", errors.New("aci: no compose-hash event")
	}
	return compose, nil
}

func trim0x(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

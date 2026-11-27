package aci

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
)

// Service is the TEE side of E2EE v2, for tests that stand in for a real
// gateway: it opens sealed request fields and seals answer fields.
type Service struct{ Key *ecdh.PrivateKey }

// Session rebuilds the request's session from its headers.
func (sv Service) Session(model string, h map[string]string) (*Session, error) {
	if h["X-E2EE-Version"] != "2" || h["X-Model-Pub-Key"] != hex.EncodeToString(sv.Key.PublicKey().Bytes()) {
		return nil, errors.New("not sealed to this service")
	}
	cb, err := hex.DecodeString(h["X-Client-Pub-Key"])
	if err != nil {
		return nil, err
	}
	cp, err := ecdh.X25519().NewPublicKey(cb)
	if err != nil {
		return nil, err
	}
	ts, err := strconv.ParseInt(h["X-E2EE-Timestamp"], 10, 64)
	if err != nil {
		return nil, err
	}
	return &Session{model: model, nonce: h["X-E2EE-Nonce"], ts: ts, service: cp, keyHex: h["X-Model-Pub-Key"]}, nil
}

// OpenField opens a sealed request field.
func (sv Service) OpenField(s *Session, field, ct string) (string, error) {
	b, err := hex.DecodeString(ct)
	if err != nil || len(b) < 60 {
		return "", errors.New("not sealed")
	}
	eph, err := ecdh.X25519().NewPublicKey(b[:32])
	if err != nil {
		return "", err
	}
	shared, err := sv.Key.ECDH(eph)
	if err != nil {
		return "", err
	}
	a, err := gcm(shared)
	if err != nil {
		return "", err
	}
	plain, err := a.Open(nil, b[32:44], b[44:], s.aad("aci.e2ee.request.v2", "", field))
	return string(plain), err
}

// SealField seals an answer field to the client key in s.
func (sv Service) SealField(s *Session, id, field, plain string) string {
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	shared, _ := eph.ECDH(s.service)
	a, _ := gcm(shared)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	out := append(eph.PublicKey().Bytes(), nonce...)
	return hex.EncodeToString(a.Seal(out, nonce, []byte(plain), s.aad("aci.e2ee.response.v2", id, field)))
}

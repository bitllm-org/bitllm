package aci

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// AlgoX25519 is the E2EE v2 suite this package speaks (spec/e2ee-v2.md §4).
const AlgoX25519 = "x25519-aes-256-gcm-hkdf-sha256"

const hkdfInfo = "aci.e2ee.v2.x25519"

// Session seals one request to a verified workload key and opens its answer.
// Use a new Session for every request: its nonce and client key are single use.
type Session struct {
	model   string
	nonce   string
	ts      int64
	service *ecdh.PublicKey
	client  *ecdh.PrivateKey
	keyHex  string
	// E2EE v2 seals message contents only. offersTools is whether the request
	// gave the model tools: without them, a tool call in the answer did not
	// come from the model. toolsInClear is whether anything about tools went
	// out readable, definitions or earlier tool calls.
	offersTools, toolsInClear bool
}

// NewSession starts a request for model, sealed to the workload key v proved.
func NewSession(v *Verified, model string, now time.Time) (*Session, error) {
	service, err := ecdh.X25519().NewPublicKey(v.Key)
	if err != nil {
		return nil, err
	}
	client, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	n := make([]byte, 32)
	rand.Read(n)
	return &Session{model: model, nonce: hex.EncodeToString(n), ts: now.Unix(),
		service: service, client: client, keyHex: hex.EncodeToString(v.Key)}, nil
}

// Headers are the five E2EE v2 request headers (spec/e2ee-v2.md §3.1).
func (s *Session) Headers() map[string]string {
	return map[string]string{
		"X-E2EE-Version":   "2",
		"X-Client-Pub-Key": hex.EncodeToString(s.client.PublicKey().Bytes()),
		"X-Model-Pub-Key":  s.keyHex,
		"X-E2EE-Nonce":     s.nonce,
		"X-E2EE-Timestamp": strconv.FormatInt(s.ts, 10),
	}
}

// HeaderNames are the request headers a relaying node passes on.
var HeaderNames = []string{"X-E2EE-Version", "X-Client-Pub-Key", "X-Model-Pub-Key", "X-E2EE-Nonce", "X-E2EE-Timestamp"}

func (s *Session) aad(purpose, id, field string) []byte {
	m := map[string]any{"purpose": purpose, "algo": AlgoX25519, "model": s.model,
		"field": field, "nonce": s.nonce, "ts": s.ts}
	if purpose == "aci.e2ee.response.v2" {
		m["id"] = id
	}
	b, _ := canonical(m)
	return b
}

func gcm(shared []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, shared, nil, hkdfInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Session) seal(field string, plain []byte) (string, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	shared, err := eph.ECDH(s.service)
	if err != nil {
		return "", err
	}
	a, err := gcm(shared)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, a.NonceSize())
	rand.Read(nonce)
	out := append(eph.PublicKey().Bytes(), nonce...)
	out = a.Seal(out, nonce, plain, s.aad("aci.e2ee.request.v2", "", field))
	return hex.EncodeToString(out), nil
}

func (s *Session) open(id, field, ct string) (string, error) {
	b, err := hex.DecodeString(trim0x(ct))
	if err != nil || len(b) < 32+12+16 {
		return "", fmt.Errorf("aci: %s is not sealed", field)
	}
	eph, err := ecdh.X25519().NewPublicKey(b[:32])
	if err != nil {
		return "", err
	}
	shared, err := s.client.ECDH(eph)
	if err != nil {
		return "", err
	}
	a, err := gcm(shared)
	if err != nil {
		return "", err
	}
	plain, err := a.Open(nil, b[32:44], b[44:], s.aad("aci.e2ee.response.v2", id, field))
	if err != nil {
		return "", fmt.Errorf("aci: %s does not open", field)
	}
	return string(plain), nil
}

// SealChat encrypts every message content of a decoded chat completions
// request in place (spec/e2ee-v2.md §5): a string content as itself, a
// structured one as its compact JSON. Tool call arguments and tool
// definitions are not covered by E2EE v2 and stay readable: ToolsInClear
// says whether the request had any.
func (s *Session) SealChat(body map[string]any) error {
	if m, _ := body["model"].(string); m != s.model {
		return errors.New("aci: request model differs from the session's")
	}
	s.offersTools = present(body["tools"]) || present(body["functions"])
	s.toolsInClear = s.offersTools
	msgs, _ := body["messages"].([]any)
	sealed := 0
	for i, m := range msgs {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		if present(msg["tool_calls"]) || present(msg["function_call"]) {
			s.toolsInClear = true
		}
		var plain []byte
		switch c := msg["content"].(type) {
		case string:
			plain = []byte(c)
		case []any:
			var b bytes.Buffer
			e := json.NewEncoder(&b)
			e.SetEscapeHTML(false)
			if err := e.Encode(c); err != nil {
				return err
			}
			plain = bytes.TrimSuffix(b.Bytes(), []byte("\n"))
		default:
			continue
		}
		ct, err := s.seal("messages."+strconv.Itoa(i)+".content", plain)
		if err != nil {
			return err
		}
		msg["content"] = ct
		sealed++
	}
	if sealed == 0 {
		return errors.New("aci: nothing to seal in this request")
	}
	return nil
}

// ToolsInClear reports whether the sealed request carried tool definitions or
// earlier tool calls. E2EE v2 leaves those readable to the peer that passes
// the request to the TEE, and the tool calls in the answer are not
// authenticated.
func (s *Session) ToolsInClear() bool { return s.toolsInClear }

// present reports whether a decoded JSON value holds anything. Null, an empty
// array and an empty object do not: servers send those when there is no tool
// call.
func present(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// choiceFields are the generated-content fields a v2 service seals.
var choiceFields = map[string][]string{
	"message": {"content", "reasoning", "reasoning_content"},
	"delta":   {"content", "reasoning", "reasoning_content"},
}

// OpenChat decrypts a chat completion, or one streamed chunk of it, in place.
// Every non-empty content field must open: a plain one means the answer did
// not come from the sealed path, and is refused. So is a tool call when the
// request offered no tools. E2EE v2 does not seal tool calls, so when it did
// offer tools they pass unchecked.
func (s *Session) OpenChat(doc map[string]any) error {
	id, _ := doc["id"].(string)
	choices, _ := doc["choices"].([]any)
	for pos, c := range choices {
		ch, ok := c.(map[string]any)
		if !ok {
			continue
		}
		idx := pos
		if n, ok := ch["index"].(json.Number); ok {
			if v, err := n.Int64(); err == nil {
				idx = int(v)
			}
		} else if f, ok := ch["index"].(float64); ok {
			idx = int(f)
		}
		for part, fields := range choiceFields {
			obj, ok := ch[part].(map[string]any)
			if !ok {
				continue
			}
			if !s.offersTools && (present(obj["tool_calls"]) || present(obj["function_call"])) {
				// The model had no tool to call, so this one was added on
				// the way.
				return fmt.Errorf("aci: choices.%d.%s has a tool call, but the request offered no tools", idx, part)
			}
			for _, f := range fields {
				v, ok := obj[f].(string)
				if !ok || v == "" {
					continue
				}
				path := "choices." + strconv.Itoa(idx) + "." + part + "." + f
				plain, err := s.open(id, path, v)
				if err != nil {
					return err
				}
				obj[f] = plain
			}
		}
	}
	return nil
}

// OpenSSELine decrypts one line of a streamed chat completion. Lines that are
// not data events, and the [DONE] marker, pass through.
func (s *Session) OpenSSELine(line []byte) ([]byte, error) {
	t := bytes.TrimRight(line, "\r\n")
	if !bytes.HasPrefix(t, []byte("data:")) {
		return line, nil
	}
	payload := bytes.TrimSpace(t[5:])
	if len(payload) == 0 || string(payload) == "[DONE]" {
		return line, nil
	}
	doc, err := decode(payload)
	if err != nil {
		return line, nil // not JSON: an error event or a keepalive, nothing sealed
	}
	if err := s.OpenChat(doc); err != nil {
		return nil, err
	}
	b, err := encode(doc)
	if err != nil {
		return nil, err
	}
	return append(append([]byte("data: "), b...), line[len(t):]...), nil
}

// OpenBody decrypts a buffered chat completion.
func (s *Session) OpenBody(body []byte) ([]byte, error) {
	doc, err := decode(body)
	if err != nil {
		return nil, fmt.Errorf("aci: bad answer: %w", err)
	}
	if err := s.OpenChat(doc); err != nil {
		return nil, err
	}
	return encode(doc)
}

func decode(b []byte) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var doc map[string]any
	if err := d.Decode(&doc); err != nil || doc == nil {
		return nil, errors.New("not a JSON object")
	}
	return doc, nil
}

func encode(doc map[string]any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(doc); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// ValidHeaderValue reports whether v is a plausible E2EE header value: short
// hex or digits. A relaying node passes on only values that pass.
func ValidHeaderValue(name, v string) bool {
	if len(v) == 0 || len(v) > 200 {
		return false
	}
	return strings.IndexFunc(trim0x(v), func(r rune) bool {
		return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F')
	}) < 0
}

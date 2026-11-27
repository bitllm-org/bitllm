package node

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"

	"github.com/bitllm-org/bitllm/internal/store"
	"github.com/libp2p/go-libp2p/core/peer"
)

// maxFirstSeen bounds the record. Once it is full, nodes not on it stay new:
// that errs on the side of the smaller quota.
const maxFirstSeen = 50000

// newFor is how long a node counts as new on this server (--new-daily).
const newFor = 24 * time.Hour

// firstSeen remembers when each node first asked this server for work, so a
// fresh node id, which costs nothing, gets the smaller --new-daily quota.
// seen.json maps node ids to Unix seconds; an operator may seed it.
type firstSeen struct {
	mu   sync.Mutex
	at   map[string]int64
	save *store.Debounced
}

func openFirstSeen(path string) *firstSeen {
	f := &firstSeen{at: map[string]int64{}}
	f.save = store.NewDebounced(path, 0o600, 0, func() ([]byte, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return json.Marshal(f.at)
	})
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &f.at); err != nil {
			log.Printf("%s: %v (starting empty)", path, err)
			f.at = map[string]int64{}
		}
	}
	return f
}

// isNew records p on first sight and reports whether it is still new at now.
func (f *firstSeen) isNew(p peer.ID, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := p.String()
	t, ok := f.at[k]
	if !ok {
		if len(f.at) >= maxFirstSeen {
			return true
		}
		f.at[k] = now.Unix()
		f.save.Mark()
		return true
	}
	return now.Sub(time.Unix(t, 0)) < newFor
}

func (f *firstSeen) Close() error { return f.save.Close() }

package oidclogout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var errRevoked = errors.New("OIDC session is revoked or expired")
var errReplay = errors.New("logout token already processed")

type identity struct {
	Issuer, ClientID, Subject, SID string
	IssuedAt, ExpiresAt            time.Time
}

type revocation struct {
	Until  int64 `json:"until"`
	Cutoff int64 `json:"cutoff,omitempty"`
}

var revocationBucket = []byte("revocations-v1")
var replayBucket = []byte("replays-v1")

// registry serializes revocation with stream registration. Its durable records
// outlive connections: an unused cookie must not become valid after logout.
type registry struct {
	mu          sync.Mutex
	db          *bolt.DB
	streams     map[uint64]*registeredStream
	sequence    uint64
	closed      bool
	lastCleanup time.Time
}

type registeredStream struct {
	identity identity
	closer   io.Closer
	timer    *time.Timer
}

func openRegistry(path string) (*registry, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open logout state (one process may own this file): %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{revocationBucket, replayBucket} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &registry{db: db, streams: make(map[uint64]*registeredStream)}, nil
}

// Keys contain only digests of identity data, never raw tokens or subjects.
func identityKey(kind, issuer, client, value string) []byte {
	b, _ := json.Marshal([]string{kind, issuer, client, value})
	sum := sha256.Sum256(b)
	return []byte(hex.EncodeToString(sum[:]))
}

func revokedIn(tx *bolt.Tx, id identity, now time.Time) (bool, error) {
	b := tx.Bucket(revocationBucket)
	for _, item := range []struct{ kind, value string }{{"sid", id.SID}, {"sub", id.Subject}} {
		if item.value == "" {
			continue
		}
		raw := b.Get(identityKey(item.kind, id.Issuer, id.ClientID, item.value))
		if raw == nil {
			continue
		}
		var record revocation
		if err := json.Unmarshal(raw, &record); err != nil {
			return false, err
		}
		if record.Until > now.Unix() && (item.kind == "sid" || id.IssuedAt.Unix() <= record.Cutoff) {
			return true, nil
		}
	}
	return false, nil
}

func (r *registry) checkLocked(id identity, now time.Time) error {
	if r.closed || !id.ExpiresAt.After(now) {
		return errRevoked
	}
	return r.db.View(func(tx *bolt.Tx) error {
		revoked, err := revokedIn(tx, id, now)
		if err != nil {
			return err
		}
		if revoked {
			return errRevoked
		}
		return nil
	})
}

func (r *registry) check(id identity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.checkLocked(id, time.Now())
}

func (r *registry) register(id identity, closer io.Closer) (func(), error) {
	r.mu.Lock()
	if err := r.checkLocked(id, time.Now()); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	r.sequence++
	key := r.sequence
	entry := &registeredStream{identity: id, closer: closer}
	r.streams[key] = entry
	entry.timer = time.AfterFunc(time.Until(id.ExpiresAt), func() { _ = closer.Close() })
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			delete(r.streams, key)
			entry.timer.Stop()
			r.mu.Unlock()
		})
	}, nil
}

func (r *registry) revoke(issuer, client string, event logoutEvent, horizon, replayTTL time.Duration) error {
	now := time.Now()
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return errors.New("logout registry closed")
	}
	cleanup := now.Sub(r.lastCleanup) > time.Minute
	err := r.db.Update(func(tx *bolt.Tx) error {
		replays := tx.Bucket(replayBucket)
		var replayKey []byte
		if event.JTI != "" {
			replayKey = identityKey("jti", issuer, client, event.JTI)
			if raw := replays.Get(replayKey); raw != nil {
				var old revocation
				if err := json.Unmarshal(raw, &old); err != nil {
					return err
				}
				if old.Until > now.Unix() {
					return errReplay
				}
			}
		}
		kind, value := "sid", event.SID
		if value == "" {
			kind, value = "sub", event.Subject
		}
		if value == "" {
			return errors.New("logout has no session identity")
		}
		key := identityKey(kind, issuer, client, value)
		record := revocation{Until: now.Add(horizon).Unix(), Cutoff: event.IssuedAt.Unix()}
		b := tx.Bucket(revocationBucket)
		if raw := b.Get(key); raw != nil {
			var old revocation
			if err := json.Unmarshal(raw, &old); err != nil {
				return err
			}
			if old.Until > record.Until {
				record.Until = old.Until
			}
			if old.Cutoff > record.Cutoff {
				record.Cutoff = old.Cutoff
			}
		}
		data, _ := json.Marshal(record)
		if err := b.Put(key, data); err != nil {
			return err
		}
		if replayKey != nil {
			data, _ = json.Marshal(revocation{Until: now.Add(replayTTL).Unix()})
			if err := replays.Put(replayKey, data); err != nil {
				return err
			}
		}
		if cleanup {
			for _, bucket := range []*bolt.Bucket{b, replays} {
				cursor := bucket.Cursor()
				for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
					var old revocation
					if err := json.Unmarshal(v, &old); err != nil {
						return err
					}
					if old.Until <= now.Unix() {
						if err := cursor.Delete(); err != nil {
							return err
						}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		r.mu.Unlock()
		return err
	}
	if cleanup {
		r.lastCleanup = now
	}
	var closing []io.Closer
	for _, entry := range r.streams {
		id := entry.identity
		if id.Issuer != issuer || id.ClientID != client {
			continue
		}
		matches := event.SID != "" && id.SID == event.SID
		if event.SID == "" {
			matches = id.Subject == event.Subject && id.IssuedAt.Unix() <= event.IssuedAt.Unix()
		}
		if matches {
			closing = append(closing, entry.closer)
		}
	}
	r.mu.Unlock()
	// Close invokes unregister, so never call it while holding mu.
	for _, closer := range closing {
		_ = closer.Close()
	}
	return nil
}

func (r *registry) Destruct() error {
	r.mu.Lock()
	r.closed = true
	closing := make([]io.Closer, 0, len(r.streams))
	for _, entry := range r.streams {
		entry.timer.Stop()
		closing = append(closing, entry.closer)
	}
	r.mu.Unlock()
	for _, closer := range closing {
		_ = closer.Close()
	}
	return r.db.Close()
}

type sessionBinding struct {
	registry *registry
	identity identity
}
type bindingKey struct{}

func bindingFromContext(ctx context.Context) (*sessionBinding, bool) {
	b, ok := ctx.Value(bindingKey{}).(*sessionBinding)
	return b, ok && b != nil
}
func (b *sessionBinding) register(c io.Closer) (func(), error) {
	return b.registry.register(b.identity, c)
}

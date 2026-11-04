package oidclogout

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

type registryTestCloser struct {
	once   sync.Once
	closed chan struct{}
	count  atomic.Int32
}

func newRegistryTestCloser() *registryTestCloser {
	return &registryTestCloser{closed: make(chan struct{})}
}

func (c *registryTestCloser) Close() error {
	c.once.Do(func() { c.count.Add(1); close(c.closed) })
	return nil
}

func (c *registryTestCloser) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func testRegistry(t *testing.T) *registry {
	t.Helper()
	r, err := openRegistry(filepath.Join(t.TempDir(), "state", "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Destruct(); err != nil {
			t.Error(err)
		}
	})
	return r
}

func testIdentity(sid string) identity {
	now := time.Now()
	return identity{Issuer: "https://id.example/realms/company", ClientID: "caddy", Subject: "user", SID: sid, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
}

func TestRegistryRevocationAndReplaySurviveReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "sessions.db")
	r, err := openRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	id := testIdentity("session")
	event := logoutEvent{Issuer: id.Issuer, SID: id.SID, Subject: id.Subject, JTI: "logout-event", IssuedAt: time.Now()}
	if err := r.revoke(id.Issuer, id.ClientID, event, time.Hour, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := r.Destruct(); err != nil {
		t.Fatal(err)
	}
	r, err = openRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Destruct()
	if err := r.check(id); !errors.Is(err, errRevoked) {
		t.Fatalf("reopened state accepted revoked cookie: %v", err)
	}
	if _, err := r.register(id, newRegistryTestCloser()); !errors.Is(err, errRevoked) {
		t.Fatalf("reopened state accepted reconnect: %v", err)
	}
	if err := r.revoke(id.Issuer, id.ClientID, event, time.Hour, time.Minute); !errors.Is(err, errReplay) {
		t.Fatalf("replay record lost: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("state file permissions=%o", info.Mode().Perm())
	}
}

func TestRegistrySIDLogoutIsScopedToIssuerAndClient(t *testing.T) {
	r := testRegistry(t)
	base := testIdentity("shared-sid")
	identities := []identity{base, base, base, base}
	identities[1].SID = "other-sid"
	identities[2].Issuer = "https://id.example/realms/another"
	identities[3].ClientID = "another-client"
	closers := make([]*registryTestCloser, len(identities))
	for i, id := range identities {
		closers[i] = newRegistryTestCloser()
		unregister, err := r.register(id, closers[i])
		if err != nil {
			t.Fatal(err)
		}
		defer unregister()
	}
	event := logoutEvent{SID: base.SID, Subject: base.Subject, JTI: "event", IssuedAt: time.Now()}
	if err := r.revoke(base.Issuer, base.ClientID, event, time.Hour, time.Minute); err != nil {
		t.Fatal(err)
	}
	for i, id := range identities {
		err := r.check(id)
		if i == 0 {
			if !errors.Is(err, errRevoked) || !closers[i].isClosed() {
				t.Fatalf("matching session survived: err=%v closed=%v", err, closers[i].isClosed())
			}
		} else if err != nil || closers[i].isClosed() {
			t.Fatalf("unrelated session %d affected: err=%v closed=%v", i, err, closers[i].isClosed())
		}
	}
}

func TestRegistrySubjectLogoutCutoffAllowsFreshLogin(t *testing.T) {
	r := testRegistry(t)
	cutoff := time.Now().Truncate(time.Second)
	old := testIdentity("old-session")
	old.IssuedAt = cutoff.Add(-time.Minute)
	otherDevice := old
	otherDevice.SID = "other-device"
	fresh := old
	fresh.SID = "fresh-session"
	fresh.IssuedAt = cutoff.Add(time.Second)
	otherUser := old
	otherUser.SID = "another-user-session"
	otherUser.Subject = "another-user"
	identities := []identity{old, otherDevice, fresh, otherUser}
	closers := make([]*registryTestCloser, len(identities))
	for i, id := range identities {
		closers[i] = newRegistryTestCloser()
		unregister, err := r.register(id, closers[i])
		if err != nil {
			t.Fatal(err)
		}
		defer unregister()
	}
	if err := r.revoke(old.Issuer, old.ClientID, logoutEvent{Subject: old.Subject, JTI: "subject-event", IssuedAt: cutoff}, time.Hour, time.Minute); err != nil {
		t.Fatal(err)
	}
	for i, id := range identities {
		shouldRevoke := i < 2
		if err := r.check(id); errors.Is(err, errRevoked) != shouldRevoke {
			t.Fatalf("identity %d revocation=%v want=%v", i, err, shouldRevoke)
		}
		if closers[i].isClosed() != shouldRevoke {
			t.Fatalf("identity %d closed=%v want=%v", i, closers[i].isClosed(), shouldRevoke)
		}
	}
	// Out-of-order subject events must never lower a previously committed cutoff.
	if err := r.revoke(old.Issuer, old.ClientID, logoutEvent{Subject: old.Subject, JTI: "older-event", IssuedAt: cutoff.Add(-time.Hour)}, time.Hour, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := r.check(old); !errors.Is(err, errRevoked) {
		t.Fatalf("older event weakened revocation: %v", err)
	}
}

func TestRegistryInvalidRevocationIsAtomic(t *testing.T) {
	r := testRegistry(t)
	id := testIdentity("session")
	closer := newRegistryTestCloser()
	unregister, err := r.register(id, closer)
	if err != nil {
		t.Fatal(err)
	}
	defer unregister()
	event := logoutEvent{JTI: "bad-event", IssuedAt: time.Now()}
	if err := r.revoke(id.Issuer, id.ClientID, event, time.Hour, time.Minute); err == nil {
		t.Fatal("accepted logout without identity")
	}
	if closer.isClosed() {
		t.Fatal("invalid logout closed a connection")
	}
	if err := r.check(id); err != nil {
		t.Fatalf("invalid logout revoked session: %v", err)
	}
	event.SID = id.SID
	if err := r.revoke(id.Issuer, id.ClientID, event, time.Hour, time.Minute); err != nil {
		t.Fatalf("failed transaction persisted replay marker: %v", err)
	}
	if !closer.isClosed() {
		t.Fatal("valid retry did not close connection")
	}
	if err := r.revoke(id.Issuer, id.ClientID, event, time.Hour, time.Minute); !errors.Is(err, errReplay) {
		t.Fatalf("duplicate accepted as fresh event: %v", err)
	}
	if count := closer.count.Load(); count != 1 {
		t.Fatalf("connection closed %d times", count)
	}
}

func TestRegistryConcurrentRegistrationAndLogoutCannotLeaveOpenStreams(t *testing.T) {
	r := testRegistry(t)
	for round := range 16 {
		id := testIdentity(fmt.Sprintf("session-%d", round))
		start := make(chan struct{})
		var wg sync.WaitGroup
		var accepted sync.Map
		for i := range 32 {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				<-start
				closer := newRegistryTestCloser()
				unregister, err := r.register(id, closer)
				if err != nil {
					if !errors.Is(err, errRevoked) {
						t.Error(err)
					}
					_ = closer.Close()
					return
				}
				accepted.Store(index, closer)
				// Keep registration active until logout's Close reaches it.
				select {
				case <-closer.closed:
					unregister()
				case <-time.After(3 * time.Second):
					t.Error("accepted stream survived logout")
					unregister()
				}
			}(i)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := r.revoke(id.Issuer, id.ClientID, logoutEvent{SID: id.SID, JTI: id.SID, IssuedAt: time.Now()}, time.Hour, time.Minute); err != nil {
				t.Error(err)
			}
		}()
		close(start)
		wg.Wait()
		accepted.Range(func(_, value any) bool {
			if !value.(*registryTestCloser).isClosed() {
				t.Error("registered stream remained open")
			}
			return true
		})
		if _, err := r.register(id, newRegistryTestCloser()); !errors.Is(err, errRevoked) {
			t.Fatalf("late reconnect allowed: %v", err)
		}
	}
}

func TestRegistryExpiryClosesIdleStreamAndUnregisterStopsTimer(t *testing.T) {
	r := testRegistry(t)
	id := testIdentity("expires")
	id.ExpiresAt = time.Now().Add(60 * time.Millisecond)
	closer := newRegistryTestCloser()
	unregister, err := r.register(id, closer)
	if err != nil {
		t.Fatal(err)
	}
	defer unregister()
	select {
	case <-closer.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("expired idle stream remained open")
	}
	if err := r.check(id); !errors.Is(err, errRevoked) {
		t.Fatalf("expired identity accepted: %v", err)
	}
	id = testIdentity("unregistered")
	id.ExpiresAt = time.Now().Add(60 * time.Millisecond)
	closer = newRegistryTestCloser()
	unregister, err = r.register(id, closer)
	if err != nil {
		t.Fatal(err)
	}
	unregister()
	unregister()
	time.Sleep(100 * time.Millisecond)
	if closer.isClosed() {
		t.Fatal("unregistered stream timer still fired")
	}
}

func TestRegistryCorruptStateFailsClosed(t *testing.T) {
	r := testRegistry(t)
	id := testIdentity("corrupt")
	if err := r.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(revocationBucket).Put(identityKey("sid", id.Issuer, id.ClientID, id.SID), []byte("invalid-json"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.check(id); err == nil {
		t.Fatal("corrupt revocation accepted a request")
	}
	if _, err := r.register(id, newRegistryTestCloser()); err == nil {
		t.Fatal("corrupt revocation accepted a stream")
	}
	if err := r.revoke(id.Issuer, id.ClientID, logoutEvent{SID: id.SID, JTI: "event", IssuedAt: time.Now()}, time.Hour, time.Minute); err == nil {
		t.Fatal("corrupt state overwritten by successful logout")
	}
}

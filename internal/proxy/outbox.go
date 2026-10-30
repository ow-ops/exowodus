package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"exowodus/internal/outbox"
	"go.mau.fi/util/exhttp"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/federation"
)

type federationOutbox struct {
	store  *outbox.Store
	key    *federation.SigningKey
	lock   io.Closer
	cancel context.CancelFunc
	done   chan struct{}
}

func (p *Proxy) loadOutbox() error {
	if _, err := os.Stat(filepath.Join(p.archive.Dir, outbox.FileName)); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if p.destServer != p.serverName {
		return errors.New("federation outbox requires the original server name")
	}
	store, err := outbox.Open(p.archive.Dir)
	if err != nil {
		return err
	}
	summary, err := store.Summary(context.Background())
	if err != nil || summary == nil {
		store.Close()
		return errors.Join(errors.New("federation outbox preparation is incomplete; retry import"), err)
	}
	if summary.ServerName != p.serverName {
		store.Close()
		return errors.New("federation outbox belongs to another server")
	}
	raw, err := p.archive.SigningKey()
	if err != nil {
		store.Close()
		return err
	}
	key, err := federation.ParseSynapseKey(strings.TrimSpace(raw))
	if err != nil {
		store.Close()
		return err
	}
	lock, err := p.archive.LockFederationOutbox()
	if err != nil {
		store.Close()
		return err
	}
	p.outbox = &federationOutbox{store: store, key: key, lock: lock}
	return nil
}

// StartOutbox retries one transaction at a time, with backoff per destination.
func (p *Proxy) StartOutbox(ctx context.Context) error {
	if p.outbox == nil {
		return nil
	}
	o := p.outbox
	if o.done != nil {
		return errors.New("federation outbox already running")
	}
	if pending, err := o.store.Pending(ctx); err != nil {
		return err
	} else if pending == 0 {
		return nil
	} else {
		slog.Info("federation outbox ready", "pending", pending)
	}
	var keys federation.ServerKeyResponse
	if _, err := p.upstream.MakeRequest(ctx, http.MethodGet, p.upstream.BuildURL(mautrix.BaseURLPath{"_matrix", "key", "v2", "server"}), nil, &keys); err != nil {
		return err
	}
	if keys.ServerName != p.serverName || keys.VerifyKeys[o.key.ID].Key != o.key.Pub {
		return errors.New("Continuwuity must use the source signing key to retry federation deliveries")
	}
	if err := keys.VerifySelfSignature(); err != nil {
		return fmt.Errorf("destination signing key response: %w", err)
	}
	ctx, o.cancel = context.WithCancel(ctx)
	o.done = make(chan struct{})
	client := federation.NewClient(p.serverName, o.key, federation.NewInMemoryCache(), exhttp.SensibleClientSettings)
	client.ResponseSizeLimit = 1 << 20
	go func() {
		defer close(o.done)
		for ctx.Err() == nil {
			delivered, err := o.store.Deliver(ctx, p.serverName, client)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				slog.Warn("federation delivery retained for retry", "err", err)
			}
			if delivered && err == nil {
				count, err := o.store.Pending(ctx)
				if err != nil {
					slog.Error("could not count pending federation deliveries", "err", err)
				} else {
					slog.Info("federation deliveries remaining", "pending", count)
					if count == 0 {
						return
					}
				}
				continue
			}
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return nil
}

func (o *federationOutbox) close() error {
	if o == nil {
		return nil
	}
	if o.cancel != nil {
		o.cancel()
		<-o.done
	}
	return errors.Join(o.store.Close(), o.lock.Close())
}

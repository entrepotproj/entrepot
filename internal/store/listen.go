package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Notification channels.
const (
	// ChannelScanVerdict carries a component id whose stored scan verdict
	// changed.
	ChannelScanVerdict = "entrepot_scan_verdict"
	// ChannelScanJobs signals that scan jobs were queued (or moved to the
	// front of the queue).
	ChannelScanJobs = "entrepot_scan_jobs"
)

// Notify sends a Postgres notification.
func (s *Store) Notify(ctx context.Context, channel, payload string) error {
	_, err := s.pool.Exec(ctx, `SELECT pg_notify($1, $2)`, channel, payload)
	return mapErr(err, "notify "+channel)
}

// Listen receives notifications on channels over a dedicated connection
// (outside the pool) and calls fn for each, until ctx ends. It reconnects
// with backoff after errors; connected reports each (re)connection or loss
// (nil error when connected).
func (s *Store) Listen(ctx context.Context, channels []string, fn func(channel, payload string), connected func(err error)) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := s.listenOnce(ctx, channels, fn, func() {
			backoff = time.Second
			connected(nil)
		})
		if ctx.Err() != nil {
			return
		}
		connected(err)
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (s *Store) listenOnce(ctx context.Context, channels []string, fn func(channel, payload string), ready func()) error {
	conn, err := pgx.ConnectConfig(ctx, s.pool.Config().ConnConfig.Copy())
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	for _, ch := range channels {
		if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{ch}.Sanitize()); err != nil {
			return err
		}
	}
	ready()
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		fn(n.Channel, n.Payload)
	}
}

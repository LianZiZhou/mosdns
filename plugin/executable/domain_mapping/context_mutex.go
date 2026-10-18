package domain_mapping

import (
	"context"

	"golang.org/x/sync/semaphore"
)

// contextMutex lets abandoned HTTP readers leave the lock queue immediately.
// DNS registration retains the ordinary Lock/Unlock transaction interface.
type contextMutex struct{ gate *semaphore.Weighted }

func newContextMutex() contextMutex { return contextMutex{gate: semaphore.NewWeighted(1)} }
func (m *contextMutex) Lock()       { _ = m.gate.Acquire(context.Background(), 1) }
func (m *contextMutex) Unlock()     { m.gate.Release(1) }
func (m *contextMutex) LockContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return m.gate.Acquire(ctx, 1)
}

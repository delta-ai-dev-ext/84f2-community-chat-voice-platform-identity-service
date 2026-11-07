package clock

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSystemClockReturnsUTC(t *testing.T) {
	t.Parallel()

	now := System{}.Now()
	assert.False(t, now.IsZero())
	assert.Equal(t, time.UTC, now.Location())
}

func TestFixedClock(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 2, 11, 12, 0, 0, 0, time.UTC)
	clk := NewFixed(start)
	assert.Equal(t, start, clk.Now())

	clk.Advance(90 * time.Minute)
	assert.Equal(t, start.Add(90*time.Minute), clk.Now())

	clk.Set(start.Add(-time.Hour))
	assert.Equal(t, start.Add(-time.Hour), clk.Now())
}

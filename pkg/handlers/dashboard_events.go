package handlers

import (
	"context"
	"time"

	"kauth/pkg/audit"
)

// discoveryGroupWindow bounds how close a discovery-only call must be to the
// primary request it's attached to. kubectl issues /api and /apis on the
// same keep-alive connection immediately before the real request, so this is
// generous relative to real-world latency.
const discoveryGroupWindow = 2 * time.Second

// sessionEventsChunkSize is how many raw rows fetchGroupedSessionEvents pulls
// from the store per round-trip while walking toward a full page of primary
// (non-discovery) rows.
const sessionEventsChunkSize = 200

// groupedEvent is a primary (non-discovery) audit.RequestEvent together with
// the discovery-only calls (exact path "/api" or "/apis") attached to it.
type groupedEvent struct {
	audit.RequestEvent
	Discovery []audit.RequestEvent
}

func isDiscoveryPath(path string) bool {
	return path == "/api" || path == "/apis"
}

// eventGrouper folds a time-ordered (newest first) stream of RequestEvents
// into groupedEvent rows one add() call at a time, so it can be fed multiple
// chunks from a paginated store query without losing state at a chunk
// boundary.
type eventGrouper struct {
	groups []groupedEvent
}

func (g *eventGrouper) add(event audit.RequestEvent) {
	if len(g.groups) > 0 && isDiscoveryPath(event.Path) {
		open := &g.groups[len(g.groups)-1]
		if !isDiscoveryPath(open.Path) && event.SessionID == open.SessionID && open.OccurredAt.Sub(event.OccurredAt) <= discoveryGroupWindow {
			open.Discovery = append(open.Discovery, event)
			return
		}
	}
	g.groups = append(g.groups, groupedEvent{RequestEvent: event})
}

// fetchGroupedSessionEvents walks store.ListSession in raw chunks, grouping
// discovery calls onto the preceding primary event, until it has collected
// enough primary rows to fill the page starting at primaryOffset, or the
// store is exhausted. A group is only ever fully in or fully out of the
// returned page.
func fetchGroupedSessionEvents(ctx context.Context, store audit.RequestStore, cluster, sessionID string, pageSize, primaryOffset int) ([]groupedEvent, bool, error) {
	grouper := &eventGrouper{}
	rawOffset := 0
	for {
		chunk, err := store.ListSession(ctx, cluster, sessionID, sessionEventsChunkSize, rawOffset)
		if err != nil {
			return nil, false, err
		}
		for _, event := range chunk {
			grouper.add(event)
		}
		rawOffset += len(chunk)
		if len(grouper.groups) > primaryOffset+pageSize || len(chunk) < sessionEventsChunkSize {
			break
		}
	}

	groups := grouper.groups
	if primaryOffset >= len(groups) {
		return nil, false, nil
	}
	end := primaryOffset + pageSize
	hasNext := len(groups) > end
	end = min(end, len(groups))
	return groups[primaryOffset:end], hasNext, nil
}

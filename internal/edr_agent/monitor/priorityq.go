package monitor

import (
	"sync"
	"sync/atomic"
	"time"
)

type Priority int

const (
	PriorityHigh   Priority = 3
	PriorityMedium Priority = 2
	PriorityLow    Priority = 1
)

func EventPriority(evt *Event) Priority {
	switch evt.Type {
	case EventAlert:
		if evt.Severity >= SeverityAlert {
			return PriorityHigh
		}
		return PriorityMedium
	case EventProcessCreate, EventProcessTerminate:
		return PriorityMedium
	default:
		return PriorityLow
	}
}

type PriorityQueue struct {
	high      chan *Event
	medium    chan *Event
	low       chan *Event
	out       chan *Event
	highCap   int
	medCap    int
	lowCap    int
	dropped   int64
	highDrop  int64
	medDrop   int64
	lowDrop   int64
	mu        sync.Mutex
}

func NewPriorityQueue(out chan *Event) *PriorityQueue {
	pq := &PriorityQueue{
		high:    make(chan *Event, 100),
		medium:  make(chan *Event, 500),
		low:     make(chan *Event, 2000),
		out:     out,
		highCap: 100,
		medCap:  500,
		lowCap:  2000,
	}
	go pq.drain()
	return pq
}

func (pq *PriorityQueue) Push(evt *Event) {
	p := EventPriority(evt)
	switch p {
	case PriorityHigh:
		select {
		case pq.high <- evt:
		default:
			atomic.AddInt64(&pq.highDrop, 1)
			pq.droppedTotal()
		}
	case PriorityMedium:
		select {
		case pq.medium <- evt:
		default:
			select {
			case pq.high <- evt:
			default:
				atomic.AddInt64(&pq.medDrop, 1)
				pq.droppedTotal()
			}
		}
	default:
		select {
		case pq.low <- evt:
		default:
			select {
			case pq.medium <- evt:
			default:
				select {
				case pq.high <- evt:
				default:
					atomic.AddInt64(&pq.lowDrop, 1)
					pq.droppedTotal()
				}
			}
		}
	}
}

func (pq *PriorityQueue) droppedTotal() {
	atomic.AddInt64(&pq.dropped, 1)
}

func (pq *PriorityQueue) drain() {
	// Priority scheduling: high > medium > low
	// Check high 3 times more often than low
	for {
		select {
		case evt := <-pq.high:
			pq.send(evt)
		case evt := <-pq.high:
			pq.send(evt)
		case evt := <-pq.high:
			pq.send(evt)
		case evt := <-pq.medium:
			pq.send(evt)
		case evt := <-pq.medium:
			pq.send(evt)
		case evt := <-pq.low:
			pq.send(evt)
		}
	}
}

func (pq *PriorityQueue) send(evt *Event) {
	select {
	case pq.out <- evt:
	default:
	}
}

func (pq *PriorityQueue) Stats() (dropped int64, high, med, low int64) {
	return atomic.LoadInt64(&pq.dropped),
		atomic.LoadInt64(&pq.highDrop),
		atomic.LoadInt64(&pq.medDrop),
		atomic.LoadInt64(&pq.lowDrop)
}

var _ = time.Second

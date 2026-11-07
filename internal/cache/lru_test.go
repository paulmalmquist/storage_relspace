package cache

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBoundedAndExpiring(t *testing.T) {
	c := New[int](2, time.Minute)
	now := time.Unix(0, 0)
	c.now = func() time.Time { return now }
	c.Put("a", 1)
	c.Put("b", 2)
	c.Get("a")
	c.Put("c", 3) // evicts b (least recently used)
	if _, ok := c.Get("b"); ok || c.Len() != 2 {
		t.Fatal("not bounded")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := c.Get("a"); ok {
		t.Fatal("expired entry returned")
	}
}

func TestMissesCoalesce(t *testing.T) {
	c := New[int](10, time.Minute)
	var loads atomic.Int32
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := c.GetOrLoad("k", func() (int, error) { loads.Add(1); <-release; return 7, nil })
			if err != nil || v != 7 {
				t.Error(v, err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if loads.Load() != 1 {
		t.Fatalf("%d loads for one key", loads.Load())
	}
	if _, err := c.GetOrLoad("e", func() (int, error) { return 0, errors.New("boom") }); err == nil {
		t.Fatal("error not returned")
	}
	if _, ok := c.Get("e"); ok {
		t.Fatal("failed load cached")
	}
}

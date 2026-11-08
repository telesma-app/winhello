package hiddenwindow

import (
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestMultipleWindowsClose(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	first, err := New(logger, "First WebAuthn test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeWindow(t, first) })

	second, err := New(logger, "Second WebAuthn test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeWindow(t, second) })

	if first.WindowHandle() == 0 || second.WindowHandle() == 0 || first.WindowHandle() == second.WindowHandle() {
		t.Fatalf("expected two distinct windows, got %v and %v", first.WindowHandle(), second.WindowHandle())
	}
	closeWindow(t, first)
	closeWindow(t, second)
}

func closeWindow(t *testing.T, window *HiddenWindow) {
	t.Helper()
	done := make(chan struct{})
	var callers sync.WaitGroup
	for range 4 {
		callers.Go(window.Close)
	}
	go func() {
		callers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("window.Close did not finish")
	}
}

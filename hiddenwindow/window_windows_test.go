package hiddenwindow

import (
	"bytes"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMultipleWindowsClose(t *testing.T) {
	var firstLogs, secondLogs bytes.Buffer

	first, err := New(slog.New(slog.NewTextHandler(&firstLogs, nil)), "First WebAuthn test")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { closeWindow(t, first) })

	second, err := New(slog.New(slog.NewTextHandler(&secondLogs, nil)), "Second WebAuthn test")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { closeWindow(t, second) })

	if first.WindowHandle() == 0 || second.WindowHandle() == 0 || first.WindowHandle() == second.WindowHandle() {
		t.Fatalf("expected two distinct windows, got %v and %v", first.WindowHandle(), second.WindowHandle())
	}

	closeWindow(t, first)
	closeWindow(t, second)

	for i, logs := range []*bytes.Buffer{&firstLogs, &secondLogs} {
		for _, message := range []string{
			"Received WM_CLOSE and issued DestroyWindow",
			"Received WM_DESTROY and issued PostQuitMessage",
		} {
			if count := strings.Count(logs.String(), message); count != 1 {
				t.Errorf("window %d: expected one %q log, got %d", i, message, count)
			}
		}
	}
}

func TestWindowsShareWndProc(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	getClassLongPtr := user32.NewProc("GetClassLongPtrW")

	if runtime.GOARCH == "386" {
		getClassLongPtr = user32.NewProc("GetClassLongW")
	}

	var firstWndProc uintptr

	for range 4 {
		window, err := New(logger, "Shared WndProc test")
		if err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() { closeWindow(t, window) })

		// GCLP_WNDPROC returns the actual callback registered with Windows.
		index := int32(-24)
		wndProc, _, err := getClassLongPtr.Call(uintptr(window.WindowHandle()), uintptr(index))

		if wndProc == 0 {
			t.Fatalf("GetClassLongPtrW failed: %v", err)
		}

		if firstWndProc == 0 {
			firstWndProc = wndProc
		} else if wndProc != firstWndProc {
			t.Fatalf("window allocated a new WndProc callback: got %#x, want %#x", wndProc, firstWndProc)
		}

		closeWindow(t, window)
	}
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

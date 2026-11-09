//go:build windows

package hiddenwindow

import (
	_ "embed"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:embed icons/shield-64.png
var smallIcon []byte

//go:embed icons/shield-256.png
var bigIcon []byte

const (
	_WM_CLOSE   = 0x0010
	_WM_DESTROY = 0x0002
)

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
)

func getModuleHandle() (windows.Handle, error) {
	ret, _, err := procGetModuleHandleW.Call(uintptr(0))
	if ret == 0 {
		return 0, err
	}

	return windows.Handle(ret), nil
}

var (
	user32 = windows.NewLazySystemDLL("user32.dll")

	procGetSystemMetrics         = user32.NewProc("GetSystemMetrics")
	procCreateIconFromResourceEx = user32.NewProc("CreateIconFromResourceEx")
	procDestroyIcon              = user32.NewProc("DestroyIcon")
	procCreateWindowExW          = user32.NewProc("CreateWindowExW")
	procDefWindowProcW           = user32.NewProc("DefWindowProcW")
	procDestroyWindow            = user32.NewProc("DestroyWindow")
	procDispatchMessageW         = user32.NewProc("DispatchMessageW")
	procGetMessageW              = user32.NewProc("GetMessageW")
	procPostQuitMessage          = user32.NewProc("PostQuitMessage")
	procRegisterClassExW         = user32.NewProc("RegisterClassExW")
	procUnregisterClassW         = user32.NewProc("UnregisterClassW")
	procSendMessage              = user32.NewProc("SendMessageW")
	procTranslateMessage         = user32.NewProc("TranslateMessage")
	procGetCursorPos             = user32.NewProc("GetCursorPos")
	procMonitorFromPoint         = user32.NewProc("MonitorFromPoint")
	procGetMonitorInfo           = user32.NewProc("GetMonitorInfoW")
)

const (
	_SM_CXICON = 11
	_SM_CYICON = 12

	_SM_CXSMICON = 49
	_SM_CYSMICON = 50
)

func getSystemMetrics(nIndex int32) int32 {
	ret, _, _ := procGetSystemMetrics.Call(uintptr(nIndex))
	return int32(ret)
}

func createIconFromResourceEx(
	iconBytes []byte,
	fIcon bool,
	dwVer uint32,
	cxDesired int32,
	cyDesired int32,
	flags uint16,
) (windows.Handle, error) {
	bIcon := 0
	if fIcon {
		bIcon = 1
	}

	ret, _, err := procCreateIconFromResourceEx.Call(
		uintptr(unsafe.Pointer(&iconBytes[0])),
		uintptr(len(iconBytes)),
		uintptr(bIcon),
		uintptr(dwVer),
		uintptr(cxDesired),
		uintptr(cyDesired),
		uintptr(flags),
	)
	if ret == 0 {
		return 0, err
	}

	return windows.Handle(ret), nil
}

const _WS_EX_APPWINDOW = 0x00040000

const (
	_WS_POPUP   = 0x80000000
	_WS_VISIBLE = 0x10000000
)

func createWindowExW(
	dwExStyle uint32,
	lpClassName *uint16,
	lpWindowName *uint16,
	dwStyle uint32,
	x, y, nWidth, nHeight int32,
	hWndParent, hMenu, hInstance windows.Handle,
	lParam uintptr) (windows.HWND, error) {
	ret, _, err := procCreateWindowExW.Call(
		uintptr(dwExStyle),
		uintptr(unsafe.Pointer(lpClassName)),
		uintptr(unsafe.Pointer(lpWindowName)),
		uintptr(dwStyle),
		uintptr(x),
		uintptr(y),
		uintptr(nWidth),
		uintptr(nHeight),
		uintptr(hWndParent),
		uintptr(hMenu),
		uintptr(hInstance),
		lParam,
	)
	if ret == 0 {
		return 0, err
	}

	return windows.HWND(ret), nil
}

func defWindowProc(hwnd windows.HWND, msg uint32, wparam, lparam uintptr) uintptr {
	ret, _, _ := procDefWindowProcW.Call(
		uintptr(hwnd),
		uintptr(msg),
		wparam,
		lparam,
	)

	return ret
}

func destroyWindow(hWnd windows.HWND) error {
	ret, _, err := procDestroyWindow.Call(uintptr(hWnd))
	if ret == 0 {
		return err
	}

	return nil
}

type _POINT struct {
	x, y int32
}

type _MSG struct {
	hwnd    syscall.Handle
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      _POINT
}

func dispatchMessage(msg *_MSG) {
	_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(msg)))
}

func getMessage(lpMsg *_MSG, hWnd windows.HWND, wMsgFilterMin, wMsgFilterMax uint32) (bool, error) {
	ret, _, err := procGetMessageW.Call(
		uintptr(unsafe.Pointer(lpMsg)),
		uintptr(hWnd),
		uintptr(wMsgFilterMin),
		uintptr(wMsgFilterMax),
	)
	if int32(ret) == -1 {
		return false, err
	}

	return int32(ret) != 0, nil
}

func postQuitMessage(exitCode int32) {
	_, _, _ = procPostQuitMessage.Call(uintptr(exitCode))
}

type _WNDCLASSEXW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     windows.Handle
	hIcon         windows.Handle
	hCursor       windows.Handle
	hbrBackground windows.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       windows.Handle
}

func registerClassEx(wcx *_WNDCLASSEXW) (uint16, error) {
	ret, _, err := procRegisterClassExW.Call(
		uintptr(unsafe.Pointer(wcx)),
	)
	if ret == 0 {
		return 0, err
	}

	return uint16(ret), nil
}

func unregisterClassW(lpClassName *uint16, hInstance windows.Handle) error {
	ret, _, err := procUnregisterClassW.Call(
		uintptr(unsafe.Pointer(lpClassName)),
		uintptr(hInstance),
	)
	if ret == 0 {
		return err
	}

	return nil
}

func sendMessage(hWnd windows.HWND, msg uint32, wParam, lParam uintptr) {
	_, _, _ = procSendMessage.Call(
		uintptr(hWnd),
		uintptr(msg),
		wParam,
		lParam,
	)
}

func translateMessage(msg *_MSG) {
	_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(msg)))
}

func getCursorPos() (*_POINT, error) {
	pt := new(_POINT)

	ret, _, err := procGetCursorPos.Call(
		uintptr(unsafe.Pointer(pt)),
	)
	if ret == 0 {
		return nil, err
	}

	return pt, nil
}

func monitorFromPoint(pt *_POINT, dwFlags uint32) (windows.Handle, error) {
	// POINT is passed by value as a single 64-bit argument on amd64 and arm64.
	ret, _, err := procMonitorFromPoint.Call(
		uintptr(uint64(uint32(pt.x))|uint64(uint32(pt.y))<<32),
		uintptr(dwFlags),
	)
	if ret == 0 {
		return 0, err
	}

	return windows.Handle(ret), nil
}

type _RECT struct {
	left   int32
	top    int32
	right  int32
	bottom int32
}
type _MONITORINFO struct {
	cbSize    uint32
	rcMonitor _RECT
	rcWork    _RECT
	dwFlags   uint32
}

func getMonitorInfoW(hMonitor windows.Handle) (*_MONITORINFO, error) {
	monitorInfo := new(_MONITORINFO)
	monitorInfo.cbSize = uint32(unsafe.Sizeof(*monitorInfo))

	ret, _, err := procGetMonitorInfo.Call(
		uintptr(hMonitor),
		uintptr(unsafe.Pointer(monitorInfo)),
	)
	if ret == 0 {
		return nil, err
	}

	return monitorInfo, nil
}

type HiddenWindow struct {
	hWnd            windows.HWND
	closeOnce       sync.Once
	closeSignalChan chan struct{}
	done            chan struct{}
}

func (hw *HiddenWindow) WindowHandle() windows.HWND {
	return hw.hWnd
}

// Close waits for the window and its resources to be released.
// It can be called repeatedly or concurrently.
func (hw *HiddenWindow) Close() {
	hw.closeOnce.Do(func() { close(hw.closeSignalChan) })
	<-hw.done
}

type initResult struct {
	hWnd windows.HWND
	err  error
}

var (
	windowClassSequence atomic.Uint64
	// NewCallback registrations cannot be freed, so every window shares one.
	wndProcCallback = syscall.NewCallback(windowProc)
	// Each window owns a locked OS thread. Register its logger before creation
	// so synchronous creation callbacks can also use it, and remove it on exit.
	windowLoggers sync.Map // map[uint32]*slog.Logger, keyed by OS thread ID
)

func windowProc(hWnd windows.HWND, msg uint32, wparam, lparam uintptr) uintptr {
	value, ok := windowLoggers.Load(windows.GetCurrentThreadId())
	if !ok {
		return defWindowProc(hWnd, msg, wparam, lparam)
	}

	logger := value.(*slog.Logger)

	switch msg {
	case _WM_CLOSE:
		if err := destroyWindow(hWnd); err != nil {
			logger.Error("DestroyWindow failed", "err", err)
		} else {
			logger.Info("Received WM_CLOSE and issued DestroyWindow")
		}
	case _WM_DESTROY:
		postQuitMessage(0)
		logger.Info("Received WM_DESTROY and issued PostQuitMessage")
	default:
		return defWindowProc(hWnd, msg, wparam, lparam)
	}

	return 0
}

func New(logger *slog.Logger, name string) (*HiddenWindow, error) {
	initResultChan := make(chan initResult)
	closeSignalExternalChan := make(chan struct{})
	done := make(chan struct{})

	go func() {
		runtime.LockOSThread()

		defer runtime.UnlockOSThread()
		defer close(done)

		threadID := windows.GetCurrentThreadId()
		windowLoggers.Store(threadID, logger)

		defer windowLoggers.Delete(threadID)

		classNameStr := fmt.Sprintf("GoHiddenWindowClass-%d-%d", windows.GetCurrentProcessId(), windowClassSequence.Add(1))
		className, _ := windows.UTF16PtrFromString(classNameStr)

		windowName, err := windows.UTF16PtrFromString(name)
		if err != nil {
			initResultChan <- initResult{err: err}
			return
		}

		var (
			hInstance windows.Handle
			atom      uint16
			hIcon     windows.Handle
			hIconSm   windows.Handle
		)

		defer func() {
			if hInstance != 0 && atom != 0 {
				if err := unregisterClassW(className, hInstance); err != nil {
					logger.Error("UnregisterClassW failed", "err", err)
				} else {
					logger.Info("Window class unregistered", "className", classNameStr, "atom", atom)
				}
			}

			if hIconSm != 0 {
				if ret, _, err := procDestroyIcon.Call(uintptr(hIconSm)); ret == 0 {
					logger.Error("DestroyIcon failed", "err", err)
				}
			}

			if hIcon != 0 {
				if ret, _, err := procDestroyIcon.Call(uintptr(hIcon)); ret == 0 {
					logger.Error("DestroyIcon failed", "err", err)
				}
			}
		}()

		hInstance, err = getModuleHandle()
		if err != nil {
			initResultChan <- initResult{err: err}
			return
		}

		hIcon, err = createIconFromResourceEx(
			bigIcon,
			true,
			0x00030000,
			getSystemMetrics(_SM_CXICON),
			getSystemMetrics(_SM_CYICON),
			0,
		)
		if err != nil {
			initResultChan <- initResult{err: err}
			return
		}

		hIconSm, err = createIconFromResourceEx(
			smallIcon,
			true,
			0x00030000,
			getSystemMetrics(_SM_CXSMICON),
			getSystemMetrics(_SM_CYSMICON),
			0,
		)
		if err != nil {
			initResultChan <- initResult{err: err}
			return
		}

		class := _WNDCLASSEXW{
			lpfnWndProc:   wndProcCallback,
			hInstance:     hInstance,
			lpszClassName: className,
			hIcon:         hIcon,
			hIconSm:       hIconSm,
		}
		class.cbSize = uint32(unsafe.Sizeof(class))

		atom, err = registerClassEx(&class)
		if err != nil {
			initResultChan <- initResult{err: err}
			return
		}

		logger.Info("Window class registered", "className", classNameStr, "atom", atom)

		pt, err := getCursorPos()
		if err != nil {
			initResultChan <- initResult{err: err}
			return
		}

		hmon, err := monitorFromPoint(pt, 0x2)
		if err != nil {
			initResultChan <- initResult{err: err}
			return
		}

		monInfo, err := getMonitorInfoW(hmon)
		if err != nil {
			initResultChan <- initResult{err: err}
			return
		}

		hWnd, err := createWindowExW(
			_WS_EX_APPWINDOW,
			className,
			windowName,
			_WS_POPUP|_WS_VISIBLE,
			monInfo.rcWork.left+(monInfo.rcWork.right-monInfo.rcWork.left)/2,
			monInfo.rcWork.top+(monInfo.rcWork.bottom-monInfo.rcWork.top)/2,
			0,
			0,
			0,
			0,
			hInstance,
			0,
		)
		if err != nil {
			initResultChan <- initResult{err: err}
			return
		}

		logger.Info("Hidden window created successfully", "hwnd", hWnd)

		initResultChan <- initResult{hWnd: hWnd}

		close(initResultChan)

		// SendMessage can safely be called from another thread
		go func() {
			select {
			case <-closeSignalExternalChan:
				logger.Info("Received external close signal, sending WM_CLOSE to window", "hwnd", hWnd)
				sendMessage(hWnd, _WM_CLOSE, 0, 0)
			case <-done:
				logger.Debug("Message loop ended, close signal listener goroutine exiting")
				return
			}
		}()

		var msg _MSG

		for {
			gotMessage, err := getMessage(&msg, 0, 0, 0)
			if err != nil {
				logger.Error("GetMessage failed", "err", err)
				return
			}

			if gotMessage {
				logger.Info("Got message", "wnd_msg", msg)
				translateMessage(&msg)
				logger.Info("Message translated", "wnd_msg", msg)
				dispatchMessage(&msg)
				logger.Info("Message dispatched", "wnd_msg", msg)
			} else {
				logger.Info("Got no message, exiting the loop")
				break
			}
		}
	}()

	res := <-initResultChan
	if res.err != nil {
		<-done
		return nil, res.err
	}

	return &HiddenWindow{
		hWnd:            res.hWnd,
		closeSignalChan: closeSignalExternalChan,
		done:            done,
	}, nil
}

func GetConsoleWindow() windows.HWND {
	ret, _, _ := procGetConsoleWindow.Call()
	return windows.HWND(ret)
}

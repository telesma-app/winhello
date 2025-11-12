go tool cgo -godefs types_webauthn.go |
        ForEach-Object { $_.Replace('*_Ctype_struct_HWND__', 'uintptr') } |
        Set-Content -Path ztypes_webauthn.go -Encoding UTF8
gofmt -w ztypes_webauthn.go

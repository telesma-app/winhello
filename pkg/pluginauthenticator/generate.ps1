go tool cgo -godefs types_pluginauthenticator.go |
        ForEach-Object { $_.Replace('package pluginauthenticator', "package pluginauthenticator`r`n`r`nimport `"golang.org/x/sys/windows`"") } |
        ForEach-Object { $_.Replace('_Ctype_struct__GUID', 'windows.GUID') } |
        ForEach-Object { $_.Replace('*_Ctype_struct_HWND__', 'windows.HWND') } |
        ForEach-Object { $_.Replace('// Code generated', "//go:build windows`r`n`r`n// Code generated") } |
        Set-Content -Path ztypes_pluginauthenticator.go -Encoding UTF8
gofmt -w ztypes_pluginauthenticator.go

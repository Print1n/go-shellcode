package main

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

const (
	buf = "改为CobaltStrike或MSF生成的shellcode"

func main() {
	base64Str := base64.StdEncoding.EncodeToString([]byte(buf))
	changeString, bytes := ChangeString(base64Str)
	fmt.Println(changeString)
	fmt.Println()
	fmt.Println(string(bytes))
}

func ChangeString(str string) (string, []byte) {
	r := rand.New(rand.NewSource(time.Now().Unix()))
	bytes := make([]byte, 4)
	for i := 0; i < 4; i++ {
		b := r.Intn(26) + 65
		bytes[i] = byte(b)
	}
	newStr := strings.Replace(str, string(bytes[0]), "#", -1)
	newStr = strings.Replace(newStr, string(bytes[1]), "!", -1)
	newStr = strings.Replace(newStr, string(bytes[2]), "@", -1)
	newStr = strings.Replace(newStr, string(bytes[3]), ")", -1)
	return newStr, bytes
}

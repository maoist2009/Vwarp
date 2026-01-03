# 需要使用 GO 1.24.1 

# 使用 export 而不是 set
export CGO_ENABLED=0
export GOOS=android
export GOARCH=arm64
export GOTOOLCHAIN=local

# 执行编译
go build -ldflags="-s -w -checklinkname=0" -o libvwarp.so ./cmd/vwarp

echo "built"

# 拷贝
cp libvwarp.so ../VwarpGUI/app/src/main/jniLibs/arm64-v8a
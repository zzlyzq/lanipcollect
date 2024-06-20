#!/bin/bash

export GOROOT=/usr/local/go
export GOPATH=/opt/go/
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin

# 定义目标操作系统和架构
targets=(
  "darwin/amd64"
  "darwin/arm64"
  "linux/386"
  "linux/amd64"
  "linux/arm"
  "linux/arm64"
  "windows/386"
  "windows/amd64"
)

# 获取Go文件名
go_file=$(ls *.go)
binary_name="${go_file%.*}"

# 编译目标文件
for target in "${targets[@]}"; do
  os_name=${target%/*}
  arch_name=${target#*/}

  output_name="${binary_name}_${os_name}_${arch_name}"
  if [ "$os_name" == "windows" ]; then
    output_name="${output_name}.exe"
  fi

  # 设置环境变量并禁用 Cgo
  #env GOOS=$os_name GOARCH=$arch_name CGO_ENABLED=0 go build -v -o $output_name $go_file
  env GOOS=$os_name GOARCH=$arch_name go build -v -o $output_name $go_file

  if [ $? -eq 0 ]; then
    echo "Successfully built $output_name"
  else
    echo "Failed to build $output_name"
  fi
done

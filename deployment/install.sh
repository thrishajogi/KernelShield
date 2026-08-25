#!/bin/bash

echo "======================================="
echo " KernelShield Environment Setup"
echo "======================================="

echo "[1/4] Updating package list..."
sudo apt update

echo "[2/4] Installing dependencies..."
sudo apt install -y \
git \
clang \
llvm \
gcc \
make \
cmake \
bpftool \
libbpf-dev \
python3 \
python3-pip \
docker.io

echo "[3/4] Checking installed versions..."

git --version
docker --version
clang --version
bpftool version
python3 --version

echo "[4/4] Setup completed successfully!"

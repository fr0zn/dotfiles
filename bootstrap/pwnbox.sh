# Packages
sudo dpkg --add-architecture i386
sudo apt-get update

# Utilities
install_package build-essential cmake
install_package libc6:i386 libc6-dev-i386 libncurses5:i386 libstdc++6:i386 # libraries (32 bits)
install_package libc6-dbg:i386 libc6-dbg
install_package gcc-multilib g++-multilib gcc-arm-none-eabi
install_package gdb gdb-multiarch
install_package socat netcat nmap net-tools wget ssh curl
install_package nasm
install_package ctags
install_package binwalk exiftool
install_package strace ltrace
install_package unzip

# ARM
install_package gcc-arm-linux-gnueabihf gcc-arm-none-eabi gcc-aarch64-linux-gnu
# arm 32
install_package libc6-dbg-armhf-cross libc6-dev-armhf-cross
# arm 64
install_package libc6-dbg-arm64-cross libc6-dev-arm64-cross
install_package qemu qemu-user qemu-user-static

install python
install python dev

install vim backup install symlink post
install tmux

install bash

install fzf

install peda
install gef
install piputils pip3 # will install unicorn, capstone, keystone-engine, ropper
install radare2
install fixenv
install libcdb
install pwntools

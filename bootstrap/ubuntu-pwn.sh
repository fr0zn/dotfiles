# Packages
sudo_run dpkg --add-architecture i386
sudo_run apt-get update

# Utilities
install_package build-essential cmake
install_package libc6:i386 libc6-dev-i386 libncurses5:i386 libstdc++6:i386 # libraries (32 bits)
install_package libc6-dbg:i386 libc6-dbg
install_package gcc-multilib g++-multilib
install_package gdb gdb-multiarch
install_package socat netcat nmap net-tools wget ssh curl
install_package nasm
install_package ctags
install_package binwalk exiftool
install_package strace ltrace
install_package unzip

# ARM
install_package gcc-arm-linux-gnueabihf gcc-5-aarch64-linux-gnu gcc-aarch64-linux-gnu
install_package libc6-dbg-armhf-cross libc6-dev-armhf-cross
install_package libc6-dbg-arm64-cross libc6-dev-arm64-cross
install_package qemu qemu-user qemu-user-static
sudo_run mkdir /etc/qemu-binfmt
sudo_run ln -s /usr/arm-linux-gnueabihf/ /etc/qemu-binfmt/arm
sudo_run ln -s /usr/aarch64-linux-gnu /etc/qemu-binfmt/aarch64

install python
install python dev

install vim
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

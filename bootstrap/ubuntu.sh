# Packages
sudo_run dpkg --add-architecture i386
install_package build-essential
install_package libc6:i386 libncurses5:i386 libstdc++6:i386 # libraries (32 bits)
install_package gcc-multilib # compile 32 bits
install_package libc6-dbg:i386 # libc symbols 32
install_package libc6-dbg # libc symbols 64

install_package fonts-hack-ttf

# GUI and terminal
install i3
install termite
install urxvt

# Tools
install_package gdb gdb-multiarch

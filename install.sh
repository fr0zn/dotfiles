install_all(){

    # Packages
    install python
    install node
    install_package cmake

    # Tools
    install vim
    install tmux

    # Utils
    install zsh
    install fzf
    install_package unzip
    install_package wget
    install_package ssh
    install pyenv

    # Extras
    install weechat
    install tmate

    # Pwn
    #install peda
    #install pwndbg
    install gef # will install ropper on python3
    install radare2
    install ropper

# end all
}

install_macos(){

    # Packages
    install_package trash
    install_package unrar
    install_package atool
    install_cask font-awesome-terminal-fonts

    # Tools
    install_cask basictex

    # Utils
    install_package reattach-to-user-namespace

    # Programs
    install iterm2
    install nimble
    install ubersicht
    install dmenumac
    install_cask appcleaner
    install_cask virtualbox
    install_cask virtualbox-extension-pack

    # Extras
    install skhd
    install chunkwm
    install macdefaults

    # Pwn
    install_cask hopper-disassembler

    # Android
    install_package ant
    install_package maven
    install_package gradle
    install_cask android-sdk
    install_cask android-ndk
    install_cask intel-haxm
    # end Android

# end macos
}

install_ubuntu(){

    # Packages
    install_package build-essential
    sudo dpkg --add-architecture i386
    install_package libc6:i386 libncurses5:i386 libstdc++6:i386 # libraries (32 bits)
    install_package gcc-multilib # compile 32 bits
    install_package libc6-dbg:i386 # libc symbols 32
    install_package libc6-dbg # libc symbols 64

    # Tools
    install_package gdb gdb-multiarch

# end ubuntu
}

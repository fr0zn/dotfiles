install_all(){

    install vim
    install tmux
    install fzf
    install zsh
    install antigen
    install weechat

    install_package unzip
    install_package wget

    install gef
    install radare2

# end all
}

install_macos(){

    install kitty
    # install iterm2
    install skhd
    install chunkwm
    install nimble

    install_package python2
    install_package node
    install_package gdb

    install_cask hopper-disassembler

    pip2 install pync # notification_center

# end macos
}

install_arch(){

    install kitty

    install_package base-devel

    install_package python3
    install_package python-pip

    install_package python2
    install_package python2-pip

# end arch
}

install_ubuntu(){

    install_package build-essential

    install_package python
    install_package python-pip

# end ubuntu
}

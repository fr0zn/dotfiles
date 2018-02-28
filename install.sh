install_all(){

    install vim
    install tmux
    install fzf
    install zsh
    install weechat

    install_package unzip
    install_package wget
    install_package ssh

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

    install_package reattach-to-user-namespace

    install_cask hopper-disassembler

    pip2 install pync # notification_center

# end macos
}

install_arch(){

    install_package base-devel

    # i3
    install_aur i3-gaps-next-git
    install_package i3blocks i3status i3lock xterm dmenu
    install_package xorg-server xorg-xinit xorg-apps xorg-fonts
    install_package adobe-source-code-pro-fonts # monospaced font
    # i3 end

    install kitty

    install_package python
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

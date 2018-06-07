install_all(){

    install vim
    install tmux
    install fzf
    install zsh
    install weechat

    install_package unzip
    install_package wget
    install_package ssh

    #install gef
    install radare2

    #install tmate

# end all
}

install_macos(){

    #install kitty
    install iterm2
    install skhd
    install chunkwm
    #install nimble

    install_package pyenv
    install_package pyenv-virtualenv
    #install_package node


    #install_package reattach-to-user-namespace
    install_package trash

    install_package unzip
    install_package unrar
    install_package atool

    install_cask hopper-disassembler
    #install_cask font-awesome-terminal-fonts
    install_cask basictex
    install_cask appcleaner

    install_cask virtualbox
    install_cask virtualbox-extension-pack

    # Android
    install_package ant
    install_package maven
    install_package gradle
    install_cask android-sdk
    install_cask android-ndk
    install_cask intel-haxm
    # end Android

    install ubersicht
    install dmenumac
    #install macdefaults

    #pip2 install pync # notification_center

# end macos
}

install_arch(){

    install_package base-devel

    # i3
    #install_aur i3-gaps-next-git
    install_package i3-gaps i3blocks i3status i3lock xterm dmenu
    install_package xorg-server xorg-xinit xorg-apps xorg-fonts
    install_package ttf-hack # monospaced font
    # i3 end

    install xorg

    install kitty

    install_package python
    install_package python-pip

    install_package python2
    install_package python2-pip

    install_package pulseaudio
    install_package pulseaudio-alsa
    install_package alsa-utils
    install_package pavucontrol

    install_package firefox-developer-edition
    install_package virtualbox

# end arch
}

install_ubuntu(){

    install_package build-essential

    install_package python
    install_package python-pip

# end ubuntu
}

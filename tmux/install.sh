backup_tmux(){
    backup_file "$HOME/.tmux.conf"
}

symlink_tmux(){
    symlink_file "tmux/tmux.conf" "$HOME/.tmux.conf"
}

install_tmux(){
    install_package "tmux"
}

install_tmux_ubuntu(){
    program_exists "tmux"
    if [[ "$?" != "0"  ]]; then
        install_package "libevent-dev"
        install_package "libncurses-dev"

        VERSION=2.6 && wget -qO- https://github.com/tmux/tmux/releases/download/${VERSION}/tmux-${VERSION}.tar.gz | tar xvz -C $DOTFILE_SRC
        cd $DOTFILE_SRC/tmux*
        ./configure && make
        sudo_run make install
    fi
}


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
    install_package "autotools-dev"
    clone https://github.com/tmux/tmux $DOTFILE_SRC/tmux
    cd $DOTFILE_SRC/tmux
    ./autogen.sh
    ./configure && make
    sudo_run make install
}


backup_tmux(){
    backup_file "$HOME/.tmux.conf"
}

symlink_tmux(){
    symlink_file "tmux/tmux.conf" "$HOME/.tmux.conf"
}

install_tmux(){
    install_package "tmux"
}


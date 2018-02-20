backup_tmux(){
    backup_file "$HOME/.tmux.conf"
}

install_tmux(){
    install_package "tmux"
}

symlink_tmux(){
    program_must_exist "tmux"
    symlink_file "tmux/tmux.conf" "$HOME/.tmux.conf"
}

install_tmux(){
    program_must_exist "tmux"
}

symlink_tmux(){
    symlink_file "tmux/tmux.conf" "$HOME/.tmux.conf"
}

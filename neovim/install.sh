backup_neovim(){
    backup_file "$HOME/.config/nvim/init.vim"
}

symlink_neovim(){
    msg_debug "Symlink neovim"
    install vim symlink
    symlink_file "neovim/init.vim" "$HOME/.config/nvim/init.vim"
}

install_neovim(){
    install_package neovim
}

post_neovim(){
    pip2 install --user neovim
}

backup_zsh(){
    backup_file "$HOME/.zshrc"
}

install_zsh(){
    install_package "zsh"
}

symlink_zsh(){
    symlink_file "zsh/zshrc" "$HOME/.zshrc"
}

post_zsh(){
    program_must_exist "zsh"
    touch $HOME/.z
    chsh -s $(which zsh)
}

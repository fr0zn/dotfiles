backup_zsh(){
    backup_file "$HOME/.zshrc"
}

install_zsh(){
    install_package "zsh" "zoxide"
    install "antigen"
}

symlink_zsh(){
    symlink_file "zsh/zshrc" "$HOME/.zshrc"
}

post_zsh(){
    program_must_exist "zsh"
    chsh -s /bin/zsh
}


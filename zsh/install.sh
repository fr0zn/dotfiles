backup_zsh(){
    backup_file "$HOME/.zshrc"
}

install_zsh(){
    install "oh-my-zsh"
    install_package "zsh" "zoxide"
}

symlink_zsh(){
    symlink_file "zsh/zshrc" "$HOME/.zshrc"
}

post_zsh(){
    program_must_exist "zsh"
    chsh -s /bin/zsh
}


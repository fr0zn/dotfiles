install_zsh(){
    install_package "zsh"
}

symlink_zsh(){
    symlink_file "zsh/zshrc" "$HOME/.zshrc"
}

pos_zsh(){
    program_must_exist "zsh"
    touch $HOME/.z
}


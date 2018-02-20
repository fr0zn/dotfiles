install_zsh(){
    install_package "zsh"
}

pos_zsh(){
    program_must_exist "zsh"
    touch $HOME/.z
}


backup_bash(){
    backup_file "$HOME/.bashrc"
}

install_bash() {
    install_package fasd
}

symlink_bash(){
    symlink_file "bash/bashrc" "$HOME/.bashrc"
    symlink_file "bash/bash_profile" "$HOME/.bash_profile"
}

post_bash(){
    program_must_exist "bash"
}


backup_bash(){
    backup_file "$HOME/.bashrc"
    backup_file "$HOME/.bash_profile"
}

install_bash() {
    install_package zoxide
}

symlink_bash(){
    symlink_file "bash/bashrc" "$HOME/.bashrc"
    symlink_file "bash/bash_profile" "$HOME/.bash_profile"
}

post_bash(){
    program_must_exist "bash"
}


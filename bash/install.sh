backup_bash(){
    backup_file "$HOME/.bashrc"
}

symlink_bash(){
    symlink_file "bash/bashrc" "$HOME/.bashrc"
    symlink_file "bash/bash_profile" "$HOME/.bash_profile"
}

post_bash(){
    program_must_exist "bash"
    touch $HOME/.z
}


backup_espanso_macos(){
    _path=$HOME/Library/Preferences/espanso
    backup_file "$_path/default.yml"
}

backup_espanso_arch(){
    _path=$HOME/.config/espanso
    backup_file "$_path/default.yml"
}

symlink_espanso_macos(){
    _path=$HOME/Library/Preferences/espanso
    symlink_file "espanso/default.yml" "$_path/default.yml"
}

symlink_espanso_arch(){
    _path=$HOME/.config/espanso
    symlink_file "espanso/default.yml" "$_path/default.yml"
}

install_espanso_macos(){
    brew tap federico-terzi/espanso
    install_package espanso
}

install_espanso_arch(){
    install_aur espanso-bin
}

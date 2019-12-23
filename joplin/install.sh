install_joplin_macos(){
    install_package joplin
}

install_joplin_arch(){
    install_aur joplin
}

symlink_joplin(){
    mkdir -p "$HOME/.config/joplin"
    symlink_file "joplin/keymap.json" "$HOME/.config/joplin"
}


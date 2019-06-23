backup_skhd_macos(){
    backup_file "$HOME/.skhdrc"
}

install_skhd_macos(){
    install_package koekeishiya/formulae/skhd
}

symlink_skhd_macos(){
    symlink_file "skhd/skhdrc" "$HOME/.skhdrc"
}

chunkwm_skhd_macos(){
    symlink_file "skhd/skhdrc_chunkwm" "$HOME/.skhdrc"
}

post_skhd_macos(){
    brew services restart skhd
}

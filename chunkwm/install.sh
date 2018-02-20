backup_chunkwm_macos(){
    backup_file "$HOME/.chunkwmrc"
}

install_chunkwm_macos(){
    brew tap crisidev/homebrew-chunkwm
    install_package chunkwm
}

symlink_chunkwm_macos(){
    symlink_file "chunkwm/chunkwmrc" "$HOME/.chunkwmrc"
}

post_chunkwm_macos(){
    brew services restart chunkwm
}

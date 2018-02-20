backup_chunkwm_macos(){
    backup_file "$HOME/.chunkwmrc"
}

install_chunkwm_macos(){
    brew tap crisidev/homebrew-chunkwm
    install_package chunkwm
}

post_chunkwm_macos(){
    brew services restart chunkwm
}

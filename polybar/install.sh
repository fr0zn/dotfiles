install_polybar_arch(){
    install_aur polybar
}

symlink_polybar(){
    mkdir -p $HOME/.config/polybar
    symlink_file "polybar/polybar" "$HOME/.config/polybar/config"
}


install_i3_ubuntu(){
    install_package i3 i3blocks xinit
}

symlink_i3_ubuntu(){
    mkdir -p $HOME/.config/i3
    symlink_file "i3/config" "$HOME/.config/i3"
}

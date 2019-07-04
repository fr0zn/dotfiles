install_kitty_macos(){
    install_cask "kitty"
}

install_kitty_arch(){
    install_package "kitty"
}

symlink_kitty(){
    local kitty_path="$HOME/.config/kitty/kitty.conf"
    symlink_file "kitty/kitty.conf" "$kitty_path"
}

symlink_kitty_macos(){
    local kitty_path="$HOME/.config/kitty/kitty.conf"
    symlink_file "kitty/kitty.conf" "$kitty_path"
}


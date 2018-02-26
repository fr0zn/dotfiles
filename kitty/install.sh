install_kitty_macos(){
    install_cask kitty
}

install_kitty_arch(){
    local path="$DOTFILE_SRC/kitty"
    clone https://aur.archlinux.org/kitty-git.git $path
    cd $path
    makepkg -si
}

symlink_kitty(){
    local kitty_path="$HOME/.config/kitty/kitty.conf"
    symlink_file "kitty/kitty.conf" "$kitty_path"
}

symlink_kitty_macos(){
    local kitty_path="$HOME/Library/Preferences/kitty/kitty.conf"
    symlink_file "kitty/kitty.conf" "$kitty_path"
}


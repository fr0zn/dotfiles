backup_yabai_macos(){
    backup_file "$HOME/.yabairc"
}

symlink_yabai_macos(){
    symlink_file "yabai/yabairc" "$HOME/.yabairc"
}

install_yabai_macos(){
    brew tap koekeishiya/formulae
    brew install yabai
}

post_yabai_macos(){
    brew services restart yabai
}

bar_yabai_macos(){
    brew install --HEAD somdoron/formulae/spacebar
    clean mkdir -p ~/.config/spacebar/
    symlink_file "yabai/spacebarrc" "$HOME/.config/spacebar/spacebarrc"
    chmod +x "$HOME/.config/spacebar/spacebarrc"
    brew services restart spacebar
}

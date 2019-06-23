backup_yabai_macos(){
    backup_file "$HOME/.yabairc"
}

symlink_yabai_macos(){
    symlink_file "yabai/yabairc" "$HOME/.yabairc"
}

install_yabai_macos(){
    brew tap koekeishiya/formulae
    brew install --HEAD yabai
}

post_yabai_macos(){
    brew services restart yabai
}

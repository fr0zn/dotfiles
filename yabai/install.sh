backup_yabai_macos(){
    backup_file "$HOME/.yabairc"
}

symlink_yabai_macos(){
    symlink_file "yabai/yabairc" "$HOME/.yabairc"
}

install_yabai_macos(){
    brew tap koekeishiya/formulae
    brew install yabai

    echo "`whoami` ALL=(root) NOPASSWD: sha256:`shasum -a 256 $(which yabai)` --load-sa" | sudo tee '/private/etc/sudoers.d/yabai'
    #sudo yabai --install-sa
}

post_yabai_macos(){
    brew services restart yabai
    sudo yabai --load-sa
    yabai -m signal --add event=dock_did_restart action="sudo yabai --load-sa"
}

bar_yabai_macos(){
    brew install --HEAD somdoron/formulae/spacebar
    clean mkdir -p ~/.config/spacebar/
    symlink_file "yabai/spacebarrc" "$HOME/.config/spacebar/spacebarrc"
    chmod +x "$HOME/.config/spacebar/spacebarrc"
    brew services restart spacebar
}

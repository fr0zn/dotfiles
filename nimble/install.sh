install_nimble_macos(){
    brew cask install nimble-commander
}

symlink_nimble_macos(){
    local conf_path="$HOME/Library/Application Support/Nimble Commander/Config"
    mkdir -p "$conf_path"
    symlink_file "nimble/Config.json" "$conf_path/Config.json"
}

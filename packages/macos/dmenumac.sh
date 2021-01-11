install_dmenumac_macos(){
    if ! is_app_installed "dmenu-mac"; then
        mkdir -p "$DOTFILE_SRC/dmenu-mac"
        rm "$DOTFILE_SRC/dmenu-mac/dmenu-mac.zip" 2> /dev/null
        curl -L "https://github.com/oNaiPs/dmenu-mac/releases/download/0.5.0/dmenu-mac.zip" > "$DOTFILE_SRC/dmenu-mac/dmenu-mac.zip"
        cd "$DOTFILE_SRC/dmenu-mac"
        unzip "dmenu-mac.zip"
        sudo mv "dmenu-mac.app" "/Applications"
    fi
}

post_dmenumac_macos(){
    open_app "dmenu-mac"
    add_app_login "dmenu-mac"
}

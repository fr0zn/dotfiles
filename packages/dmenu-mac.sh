install_dmenu-mac_macos(){
    if ! is_app_installed "dmenu-mac"; then
        mkdir -p "$DOTFILE_SRC/dmenu-mac"
        curl -L "https://github.com/fr0zn/dmenu-mac/releases/download/0.5/dmenu-mac.zip" > "$DOTFILE_SRC/dmenu-mac/dmenu-mac.zip"
        cd "$DOTFILE_SRC/dmenu-mac"
        unzip "dmenu-mac.zip"
        sudo mv "dmenu-mac.app" "/Applications"
    fi
}


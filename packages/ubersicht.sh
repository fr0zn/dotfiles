install_ubersicht_macos(){
    install_cask ubersicht
}

post_ubersicht_macos(){
     clone https://github.com/fr0zn/i3-statusbar.git "$HOME/Library/Application Support/Übersicht/widgets/i3-statusbar"
     open_app "Übersicht"
     add_app_login "Übersicht"
}

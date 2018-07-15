install_ranger_ubuntu(){
    install_package ranger caca-utils highlight atool w3m poppler-utils mediainfo
}

symlink_ranger_ubuntu(){
    msg_debug "Symlink ranger"
}

post_ranger_ubuntu(){
    # File viewers
    install_package sxiv zathura
}

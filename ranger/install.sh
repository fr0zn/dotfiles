install_ranger_ubuntu(){
    install_package ranger caca-utils highlight atool w3m poppler-utils mediainfo
}

install_ranger_macos(){
    install_package ranger
}

install_ranger_arch(){
    install_package ranger
}

symlink_ranger(){
    mkdir -p $HOME/.config/ranger
    mkdir -p $HOME/.config/ranger/plugins
    symlink_file "ranger/rc.conf" "$HOME/.config/ranger"
    symlink_file "ranger/rifle.conf" "$HOME/.config/ranger"
    symlink_file "ranger/scope.sh" "$HOME/.config/ranger"
    symlink_file "ranger/commands.py" "$HOME/.config/ranger"
    symlink_file "ranger/plugins/fasd.py" "$HOME/.config/ranger/plugins/plugin_fasd_log.py"
}

post_ranger(){
    # File viewers
    install_package sxiv
    install zathura
}

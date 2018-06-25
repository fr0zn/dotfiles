backup_urxvt_ubuntu(){
    backup_file "$HOME/.Xresources"
}

symlink_urxvt_ubuntu(){
    symlink_file "urxvt/Xresources" "$HOME/.Xresources"
}

install_urxvt_ubuntu(){
    install_package rxvt-unicode-256color x11-xserver-utils
}

post_urxvt_ubuntu(){
    xrdb ~/.Xresources
}

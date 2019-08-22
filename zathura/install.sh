backup_zathura(){
    backup_file "$HOME/.config/zathura/zathurarc"
}

symlink_zathura(){
    mkdir -p "$HOME/.config/zathura/zathurarc" 2>/dev/null
    symlink_file "zathura/zathurarc" "$HOME/.config/zathura/zathurarc"
}

install_zathura_arch(){
    install_package zathura zathura-pdf-mupdf
}

install_zathura_ubuntu(){
    install_package zathura
}

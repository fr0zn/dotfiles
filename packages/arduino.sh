install_arduino(){
    install_cask arduino
}

post_arduino_macos(){
    brew tap mengbo/ch340g-ch34g-ch34x-mac-os-x-driver https://github.com/mengbo/ch340g-ch34g-ch34x-mac-os-x-driver
    install_cask wch-ch34x-usb-serial-driver
    msg_info "Reboot mac"
}

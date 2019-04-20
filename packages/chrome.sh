install_chrome_ubuntu(){
    pushd /tmp
    wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
    sudo_run dpkg -i google-chrome-stable_current_amd64.deb
    rm google-chrome-stable_current_amd64.deb
}

install_chrome_arch(){
    install_aur google-chrome
}

install_chrome_macos(){
    install_package google-chrome
}

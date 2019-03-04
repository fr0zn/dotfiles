install_sublime_macos(){
    install_cask sublime-text
}

install_sublime_ubuntu(){
    wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | sudo apt-key add -
    install_package apt-transport-https
    echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list
    DB_SYNC=0
    install_package sublime-text

}

install_sublime_arch(){
    curl -O https://download.sublimetext.com/sublimehq-pub.gpg && sudo pacman-key --add sublimehq-pub.gpg && sudo pacman-key --lsign-key 8A8F901A && rm sublimehq-pub.gpg
    echo -e "\n[sublime-text]\nServer = https://download.sublimetext.com/arch/stable/x86_64" | sudo tee -a /etc/pacman.conf
    install_package sublime-text
}

post_sublime_macos(){
    local conf_path="$HOME/Library/Application Support/Sublime Text 3/Packages/User/"
    mkdir -p "$conf_path"
    symlink_file "sublime/Preferences.sublime-settings" "$conf_path/Preferences.sublime-settings"
    symlink_file "sublime/Package Control.sublime-settings" "$conf_path/Package Control.sublime-settings"

    # Enable key-repeat in vim mode
    defaults write com.sublimetext.3 ApplePressAndHoldEnabled -bool false

}

post_sublime_ubuntu(){
    local conf_path="$HOME/.config/sublime-text-3/Packages/User"
    mkdir -p "$conf_path"
    symlink_file "sublime/Preferences.sublime-settings" "$conf_path/Preferences.sublime-settings"
    symlink_file "sublime/Package Control.sublime-settings" "$conf_path/Package Control.sublime-settings"

    # Package control
    conf_path="$HOME/.config/sublime-text-3/Installed Packages/"
    mkdir -p "$conf_path"
    curl https://packagecontrol.io/Package%20Control.sublime-package > "$conf_path/Package Control.sublime-package"

}

post_sublime_arch(){
    post_sublime_ubuntu
}

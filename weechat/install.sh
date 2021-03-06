backup_weechat(){
    backup_path "$HOME/.weechat"
}

symlink_weechat(){
    symlink_path "weechat/config" "$HOME/.weechat"
}

install_weechat_macos(){
    brew install weechat --with-perl --with-python
}

install_weechat_arch(){
    install_package weechat
}

install_weechat_ubuntu(){
    clean sudo_run 'echo "deb https://weechat.org/ubuntu $(lsb_release -cs) main" > /etc/apt/sources.list.d/weechat.list'
    clean sudo_run 'apt-key adv --keyserver keys.gnupg.net --recv-keys 11E9DE8848F2B65222AA75B8D1820DB22A11534E'
    DB_SYNC=0
    install_package 'weechat weechat-plugins weechat-python weechat-perl'
}

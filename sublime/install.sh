install_sublime_macos(){
    install_cask sublime-text
}

post_sublime_macos(){
    local conf_path="$HOME/Library/Application Support/Sublime Text 3/Packages/User/"
    mkdir -p "$conf_path"
    symlink_file "sublime/Preferences.sublime-settings" "$conf_path/Preferences.sublime-settings"
    symlink_file "sublime/Package Control.sublime-settings" "$conf_path/Package Control.sublime-settings"
}

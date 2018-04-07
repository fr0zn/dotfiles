install_iterm2_macos(){
    brew cask install iterm2
}

symlink_iterm2_macos(){
    # Tell iTerm2 to use the custom preferences in the directory
    defaults write com.googlecode.iterm2.plist LoadPrefsFromCustomFolder -bool true
    # Specify the preferences directory
    defaults write com.googlecode.iterm2.plist PrefsCustomFolder -string "$DOTFILE_PATH/iterm2"
}

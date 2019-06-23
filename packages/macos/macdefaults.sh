install_macdefaults_macos(){

    # Small dock icons
    # defaults write com.apple.dock tilesize -int 1

    # Orient the dock on the bottom
    defaults write com.apple.Dock orientation -string bottom

    # Automatically hide and show the Dock
    defaults write com.apple.dock autohide -bool true

    #Only active apps
    defaults write com.apple.dock static-only -bool FALSE

    # Hide desktop icons
    defaults write com.apple.finder CreateDesktop false

    # Disable automatic spaces rearrange
    defaults write com.apple.dock mru-spaces -bool false

    # Set Nimble Commander as the default viewer
    # defaults write -g NSFileViewer -string info.filesmanager.Files

    # Disable spotlight indexing
    sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.metadata.mds.plist

    killall Dock
    killall Finder
}

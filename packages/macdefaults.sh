install_macdefaults_macos(){

    # Small dock icons
    defaults write com.apple.dock tilesize -int 1

    # Orient the dock on the right
    defaults write com.apple.Dock orientation -string bottom

    # Automatically hide and show the Dock
    defaults write com.apple.dock autohide -bool true

    #Only active apps
    defaults write com.apple.dock static-only -bool FALSE

    killall Dock
}
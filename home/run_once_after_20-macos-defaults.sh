#!/bin/bash
[ "$(uname)" = "Darwin" ] || exit 0

# Orient the dock on the bottom
defaults write com.apple.Dock orientation -string bottom

# Automatically hide and show the Dock
defaults write com.apple.dock autohide -bool true

# Only active apps
defaults write com.apple.dock static-only -bool FALSE

# Hide desktop icons
defaults write com.apple.finder CreateDesktop false

# Disable automatic spaces rearrange
defaults write com.apple.dock mru-spaces -bool false

# Don't switch spaces when an app steals focus
defaults write com.apple.dock workspaces-auto-swoosh -bool false

# Free trackpad swipes for OmniWM (3-finger Overview, 4-finger workspace switch)
defaults write com.apple.AppleMultitouchTrackpad TrackpadThreeFingerVertSwipeGesture -int 0
defaults write com.apple.AppleMultitouchTrackpad TrackpadFourFingerVertSwipeGesture -int 0
defaults write com.apple.AppleMultitouchTrackpad TrackpadFourFingerHorizSwipeGesture -int 0
defaults write com.apple.driver.AppleBluetoothMultitouch.trackpad TrackpadThreeFingerVertSwipeGesture -int 0
defaults write com.apple.driver.AppleBluetoothMultitouch.trackpad TrackpadFourFingerVertSwipeGesture -int 0
defaults write com.apple.driver.AppleBluetoothMultitouch.trackpad TrackpadFourFingerHorizSwipeGesture -int 0
defaults -currentHost write -g com.apple.trackpad.threeFingerVertSwipeGesture -int 0
defaults -currentHost write -g com.apple.trackpad.fourFingerVertSwipeGesture -int 0
defaults -currentHost write -g com.apple.trackpad.fourFingerHorizSwipeGesture -int 0

killall Dock
killall Finder

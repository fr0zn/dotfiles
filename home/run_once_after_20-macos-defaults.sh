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

killall Dock
killall Finder

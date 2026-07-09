#!/bin/bash
[ "$(uname)" = "Darwin" ] || exit 0

# iTerm2 reads/writes its prefs from ~/.config/iterm2 (managed by chezmoi).
# After changing prefs in iTerm2, run: chezmoi re-add ~/.config/iterm2/com.googlecode.iterm2.plist
defaults write com.googlecode.iterm2 PrefsCustomFolder -string "$HOME/.config/iterm2"
defaults write com.googlecode.iterm2 LoadPrefsFromCustomFolder -bool true

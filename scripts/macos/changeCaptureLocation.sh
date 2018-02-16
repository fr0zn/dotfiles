#!/bin/sh

if [[ -z $1 ]]; then
    exit 1
fi

defaults write com.apple.screencapture location $1
killall SystemUIServer

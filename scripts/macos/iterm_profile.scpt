#!/usr/bin/osascript
on run argv
    set argv_s to argv as text
    tell application "iTerm2"
      create window with profile argv_s
    end tell
end run

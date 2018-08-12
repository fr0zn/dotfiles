#!/usr/bin/osascript
on run argv
    set saveTID to text item delimiters
    set text item delimiters to " "
    set argv_s to argv as text
    set text item delimiters to saveTID
    tell application "iTerm2"
      create window with profile "default"
      activate
      tell current window
        if (count of argv) > 0 then
            tell current session
                write text argv_s
                write text "clear"
            end tell
        end if
      end tell
    end tell
end run

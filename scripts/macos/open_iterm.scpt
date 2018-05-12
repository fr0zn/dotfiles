#!/usr/bin/osascript
on run argv
    set saveTID to text item delimiters
    set text item delimiters to " "
    set argv_s to argv as text
    set text item delimiters to saveTID

    tell application "iTerm"
      activate
      tell current window
            create tab with default profile
            if (count of argv) > 0 then
                tell current session
                    write text argv_s
                end tell
            end if
      end tell
    end tell
end run

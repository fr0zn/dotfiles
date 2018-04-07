#!/usr/bin/osascript
on run argv
    set saveTID to text item delimiters
    set text item delimiters to " "
    set argv_s to argv as text
    set text item delimiters to saveTID

    tell application "iTerm"
        activate
        tell application "System Events"
            tell process "iTerm"
                keystroke "t" using command down
                keystroke argv_s
                key code 52
                #keystroke "clear\n"
            end tell
        end tell
    end tell
end run

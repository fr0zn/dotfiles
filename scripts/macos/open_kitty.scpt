tell application "Kitty"
    if it is running then
        activate
        tell application "System Events" to keystroke "n" using command down
    else
        reopen
        activate
    end if
end tell

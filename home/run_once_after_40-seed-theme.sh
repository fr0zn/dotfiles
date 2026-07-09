#!/bin/bash
# Mutable theme state (written by theme-switch, read by vimrc) — seeded once, not managed.
[ -f "$HOME/.config/theme" ] || echo dark > "$HOME/.config/theme"

---
name: verify
description: Verify chezmoi-managed dotfiles changes end-to-end on this Mac — drive zsh/tmux/vim/kitty, not just chezmoi diff.
---

# Verifying dotfiles changes

Source state: `home/` (see `.chezmoiroot`); sourceDir is `~/.dotfiles`.

## Converged state
```sh
chezmoi doctor          # 0 errors (dirty-tree warnings are fine pre-commit)
chezmoi diff            # empty when converged
chezmoi verify          # exit 0
chezmoi apply           # second run must be silent (idempotent)
```

## Drive the surfaces
- **zsh + tmux** (isolated server, real pty — shows prompt, env banners):
  ```sh
  tmux -L verify new-session -d -s v -x 120 -y 30 && sleep 2
  tmux -L verify send-keys -t v "type theme-switch mk y; alias term" Enter
  tmux -L verify capture-pane -t v -p   # expect functions from ~/.config/shell
  tmux -L verify kill-server
  ```
- **vim** (colorscheme follows ~/.config/theme; plug count):
  ```sh
  vim --not-a-term '+call writefile([trim(execute("colorscheme")), "plugs=" . len(g:plugs)], "/tmp/v.txt")' +qall!
  cat /tmp/v.txt   # jellybeans (dark) / ayu (light), plugs=31
  ```
- **kitty** (live instance, briefly opens a window):
  ```sh
  KY=/Applications/kitty.app/Contents/MacOS
  $KY/kitty --listen-on unix:/tmp/kv -o allow_remote_control=yes --detach; sleep 2
  $KY/kitten @ --to unix:/tmp/kv get-colors | grep '^background'   # #121212 dark / #fafafa light
  $KY/kitten @ --to unix:/tmp/kv close-window --self
  ```
- **Theme round-trip** (flips OS appearance for a few seconds):
  `zsh -i -c 'theme-switch light'` → kitty bg goes #fafafa live; switch back to dark.
- **Fresh-machine probe**: `chezmoi apply --destination $(mktemp -d) --exclude externals,scripts`
  then `find` it — must contain all managed files.

## Gotchas
- `rm` is aliased to `trash` in interactive shells sourced from the profile — use `/bin/rm` in scripts.
- kitty has no `--debug-config` anymore; use `kitty +runpy` with `kitty.config.load_config` to parse confs headlessly.
- run_once script state lives in `~/.config/chezmoi/chezmoistate.boltdb`; `chezmoi state delete-bucket --bucket=scriptState` to force re-run.

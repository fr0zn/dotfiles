# fr0zn dotfiles

Managed with [chezmoi](https://www.chezmoi.io/). The source state lives under
[`home/`](home/) (see [`.chezmoiroot`](.chezmoiroot)).

## New machine

```sh
sh -c "$(curl -fsLS get.chezmoi.io)" -- init --apply fr0zn
```

That single command installs chezmoi, clones this repo, installs Homebrew
packages, deploys every config, and runs the one-time macOS setup.

> On this machine the repo is kept at `~/.dotfiles` instead of chezmoi's
> default location, via `sourceDir = "~/.dotfiles"` in
> `~/.config/chezmoi/chezmoi.toml`.

## Day to day

| Command | What it does |
|---|---|
| `chezmoi edit ~/.zshrc` | edit the source of a managed file |
| `chezmoi diff` | preview pending changes |
| `chezmoi apply` | deploy changes (and run changed scripts) |
| `chezmoi re-add <file>` | capture local edits back into the source |
| `chezmoi update` | git pull + apply (sync another machine) |
| `chezmoi cd` | open a shell in the source repo |

## Layout

- `home/dot_*` — files deployed into `$HOME` (`dot_zshrc` → `~/.zshrc`, …)
- `home/dot_config/shell/` — shared shell config sourced by `~/.zshrc`
  (`allrc` loads path/env/aliases/exports/functions + macOS extras)
- `home/.chezmoidata/packages.yaml` — Homebrew taps/formulae/casks; installed
  by `run_onchange_before_10-packages.sh.tmpl` whenever the list changes
- `home/.chezmoiexternal.toml` — auto-updated externals (oh-my-zsh, vim-plug)
- `home/run_once_after_*` — one-time machine setup (macOS defaults, iTerm2
  prefs location, theme seed)

## Notes

- **iTerm2** loads prefs from `~/.config/iterm2` (managed). After changing
  settings in iTerm2, run
  `chezmoi re-add ~/.config/iterm2/com.googlecode.iterm2.plist`.
- **Theme**: `theme-switch light|dark` toggles macOS appearance and writes
  `~/.config/theme` (read by vim). This file is seeded once, not managed.
- The previous hand-rolled bootstrap system (multi-distro `bootstrap.sh`,
  per-package `install.sh`, Linux/pwn profiles) lives in git history — tag
  [`pre-chezmoi`](../../tree/pre-chezmoi).

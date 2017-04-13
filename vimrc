" Vundle {
" vim: set sw=4 ts=4 sts=4 et tw=78 foldmarker={,} foldlevel=0 foldmethod=marker spell:
  set nocompatible              " be iMproved, required
  filetype off                  " required
  set rtp+=~/.vim/bundle/Vundle.vim
  call vundle#begin()
  Plugin 'VundleVim/Vundle.vim'
  Plugin 'Valloric/YouCompleteMe'
  Plugin 'vim-scripts/a.vim'
  Plugin 'majutsushi/tagbar'
  Plugin 'scrooloose/nerdtree'
  Plugin 'scrooloose/nerdcommenter'
  Plugin 'vim-airline/vim-airline'
  Plugin 'vim-airline/vim-airline-themes'
  Plugin 'easymotion/vim-easymotion'
  Plugin 'airblade/vim-gitgutter'
  Plugin 'tpope/vim-fugitive'
  Plugin 'godlygeek/tabular'
  Plugin 'Raimondi/delimitMate'
  Plugin 'christoomey/vim-tmux-navigator'
  Plugin 'tpope/vim-surround'
  Plugin 'justinmk/vim-syntax-extra'
  Plugin 'SirVer/ultisnips'
  Plugin 'honza/vim-snippets'
  Plugin 'mbbill/undotree'
  Plugin 'morhetz/gruvbox'
  Plugin 'terryma/vim-multiple-cursors'
  Plugin 'dhruvasagar/vim-table-mode'
  Plugin 'itchyny/calendar.vim'
  call vundle#end()            " required
  filetype plugin indent on    " required

" }
" General {

    set background=dark         " Assume a dark background
    filetype plugin indent on   " Automatically detect file types.
    syntax on                   " Syntax highlighting
    set mousehide               " Hide the mouse cursor while typing
    "au BufNew,BufRead  * set nospell
    autocmd VimEnter * set nospell
    scriptencoding utf-8

    set clipboard=unnamed

    " Always switch to the current file directory
    autocmd BufEnter * if bufname("") !~ "^\[A-Za-z0-9\]*://" | lcd %:p:h | endif
    set rtp+=/usr/local/opt/fzf

    " Go last file cursor position
    function! ResCur()
        if line("'\"") <= line("$")
            silent! normal! g`"
            return 1
        endif
    endfunction

    augroup ResCur
        autocmd!
        autocmd BufWinEnter * call ResCur()
    augroup END

    set autowrite                       " Automatically write a file when leaving a modified buffer
    set shortmess+=filmnrxoOtT          " Abbrev. of messages (avoids 'hit enter')
    set viewoptions=folds,options,cursor,unix,slash " Better Unix / Windows compatibility
    set virtualedit=onemore             " Allow for cursor beyond last character
    set history=1000                    " Store a ton of history (default is 20)
    set timeoutlen=500                  " Time to wait for end of command
    set spell                           " Spell checking on
    set hidden                          " Allow buffer switching without saving
    set iskeyword-=.                    " '.' is an end of word designator
    set iskeyword-=#                    " '#' is an end of word designator
    set iskeyword-=-                    " '-' is an end of word designator

    set backup                      " Backups are nice ...
    set undofile                " So is persistent undo ...
    set undolevels=1000         " Maximum number of changes that can be undone
    set undoreload=10000        " Maximum number lines to save for undo on a buffer reload

" }
" Vim UI {

    if filereadable(expand("~/.vim/bundle/gruvbox/colors/gruvbox.vim"))
        colorscheme gruvbox
    endif
    set tabpagemax=15               " Only show 15 tabs
    set showmode                    " Display the current mode

    set cursorline                  " Highlight current line

    highlight clear SignColumn      " SignColumn should match background
    highlight clear LineNr          " Current line number row will have same background color in relative mode

    set ruler                   " Show the ruler
    set rulerformat=%30(%=\:b%n%y%m%r%w\ %l,%c%V\ %P%) " A ruler on steroids
    set showcmd                 " Show partial commands in status line and
                                " Selected characters/lines in visual mode

    set laststatus=2
    if has("gui_running")
        set guioptions-=R
        set guioptions-=r
        set guifont=Meslo\ LG\ M\ for\ Powerline

        set guioptions-=L
        set guioptions-=l
    endif
    " Broken down into easily includeable segments
    set statusline=%<%f\                     " Filename
    set statusline+=%w%h%m%r                 " Options
    set statusline+=\ [%{&ff}/%Y]            " Filetype
    set statusline+=\ [%{getcwd()}]          " Current dir
    set statusline+=%=%-14.(%l,%c%V%)\ %p%%  " Right aligned file nav info

    set backspace=indent,eol,start  " Backspace for dummies
    set linespace=0                 " No extra spaces between rows
    set number                      " Line numbers on
    set showmatch                   " Show matching brackets/parenthesis
    set incsearch                   " Find as you type search
    set hlsearch                    " Highlight search terms
    set winminheight=0              " Windows can be 0 line high
    set ignorecase                  " Case insensitive search
    set smartcase                   " Case sensitive when uc present
    "set selection=exclusive         " Selection match what you see
    set wildmenu                    " Show list instead of just completing
    set wildmode=list:longest,full  " Command <Tab> completion, list matches, then longest common part, then all.
    set whichwrap=b,s,h,l,<,>,[,]   " Backspace and cursor keys wrap too
    set scrolljump=5                " Lines to scroll when cursor leaves screen
    set scrolloff=3                 " Minimum lines to keep above and below cursor
    set foldenable                  " Auto fold code
    set list
    set listchars=tab:›\ ,trail:•,extends:#,nbsp:. " Highlight problematic whitespace

" }
" Formatting {

    set nowrap                      " Do not wrap long lines
    set autoindent                  " Indent at the same level of the previous line
    set shiftwidth=4                " Use indents of 4 spaces
    set expandtab                   " Tabs are spaces, not tabs
    set tabstop=4                   " An indentation every four columns
    set softtabstop=4               " Let backspace delete indent
    set nojoinspaces                " Prevents inserting two spaces after punctuation on a join (J)
    set splitright                  " Puts new vsplit windows to the right of the current
    set splitbelow                  " Puts new split windows to the bottom of the current
    set pastetoggle=<F2>           " pastetoggle (sane indentation on pastes)
    nnoremap <silent> <F5> :let _s=@/<Bar>:%s/\s\+$//e<Bar>:let @/=_s<Bar>:nohl<CR> " Remove trailings
    " Remove Trailing whitespaces
    autocmd FileType c,cpp,java,go,php,javascript,puppet,python,rust,twig,xml,yml,perl,sql autocmd BufWritePre <buffer> if !exists('g:spf13_keep_trailing_whitespace') | call StripTrailingWhitespace() | endif
" }
" Key (re)Mappings {

    let mapleader = ','

    map <C-J> <C-W>j<C-W>_
    map <C-K> <C-W>k<C-W>_
    map <C-L> <C-W>l<C-W>_
    map <C-H> <C-W>h<C-W>_

    " Wrapped lines goes down/up to next row, rather than next line in file.
    noremap j gj
    noremap k gk


    if has("user_commands")
        command! -bang -nargs=* -complete=file E e<bang> <args>
        command! -bang -nargs=* -complete=file W w<bang> <args>
        command! -bang -nargs=* -complete=file Wq wq<bang> <args>
        command! -bang -nargs=* -complete=file WQ wq<bang> <args>
        command! -bang Wa wa<bang>
        command! -bang WA wa<bang>
        command! -bang Q q<bang>
        command! -bang QA qa<bang>
        command! -bang Qa qa<bang>
    endif

    " Yank from the cursor to the end of the line, to be consistent with C and D.
    nnoremap Y y$

    nmap <silent> <leader>/ :nohlsearch<CR>

    " Visual shifting (does not exit Visual mode)
    vnoremap < <gv
    vnoremap > >gv

    " Allow using the repeat operator with a visual selection (!)
    vnoremap . :normal .<CR>

    " For when you forget to sudo.. Really Write the file.
    cmap w!! w !sudo tee % >/dev/null

    " Map <Leader>ff to display all lines with keyword under cursor
    " and ask which one to jump to
    " nmap <Leader>ff [I:let nr = input("Which one: ")<Bar>exe "normal " . nr ."[\t"<CR>

    " Easier horizontal scrolling
    map zl zL
    map zh zH
    " Easier buffer change
    map gn :bn<cr>
    map gp :bp<cr>
    map <leader>d :bd<cr>
    " FZF finder
    map <leader>ff :FZF<cr>
    " Easier formatting
    "nnoremap <silent> <leader>q gwip
    " Window manage
    nnoremap <Leader>w <c-w>

" }
" Plugins {
    " YouCompleteMe {
        let g:ycm_global_ycm_extra_conf = '~/.vim/ycm_extra_conf.py'
        let g:acp_enableAtStartup = 0
        " enable completion from tags
        let g:ycm_collect_identifiers_from_tags_files = 1

        " remap Ultisnips for compatibility for YCM
        let g:UltiSnipsExpandTrigger = '<C-j>'
        let g:UltiSnipsJumpForwardTrigger = '<C-j>'
        let g:UltiSnipsJumpBackwardTrigger = '<C-k>'

        " Enable omni completion.
        autocmd FileType css setlocal omnifunc=csscomplete#CompleteCSS
        autocmd FileType html,markdown setlocal omnifunc=htmlcomplete#CompleteTags
        autocmd FileType javascript setlocal omnifunc=javascriptcomplete#CompleteJS
        autocmd FileType python setlocal omnifunc=pythoncomplete#Complete
        autocmd FileType xml setlocal omnifunc=xmlcomplete#CompleteTags
        autocmd FileType ruby setlocal omnifunc=rubycomplete#Complete
        autocmd FileType haskell setlocal omnifunc=necoghc#omnifunc

        "nnoremap <leader>gd :YcmCompleter GoToDeclaration<CR>
        "nnoremap <leader>gf :YcmCompleter GoToDefinition<CR>
        " Haskell post write lint and check with ghcmod
        " $ `cabal install ghcmod` if missing and ensure
        " ~/.cabal/bin is in your $PATH.
        if !executable("ghcmod")
            autocmd BufWritePost *.hs GhcModCheckAndLintAsync
        endif

        " For snippet_complete marker.
        if !exists("g:spf13_no_conceal")
            if has('conceal')
                set conceallevel=2 concealcursor=i
            endif
        endif

        " Disable the neosnippet preview candidate window
        " When enabled, there can be too much visual noise
        " especially when splits are used.
        set completeopt-=preview
        let g:ycm_error_symbol = '✘'
        let g:ycm_warning_symbol = '⚠️'
    " }
    " A {
         nmap <leader>a :A<CR>
         nmap <leader>av :AV<CR>
    " }
    " TagBar {
        if isdirectory(expand("~/.vim/bundle/tagbar/"))
            nnoremap <silent> <leader>t :TagbarToggle<CR>
            let g:tagbar_autofocus = 1
            let g:tagbar_autoclose = 1
        endif
    "}
    " NerdTree {
        map <leader>e :NERDTreeFind<CR>

        let NERDTreeShowBookmarks=1
        let NERDTreeIgnore=['\.py[cd]$', '\~$', '\.swo$', '\.swp$', '^\.git$', '^\.hg$', '^\.svn$', '\.bzr$','\.DS_Store']
        let NERDTreeChDirMode=0
        let NERDTreeQuitOnOpen=1
        let NERDTreeMouseMode=2
        let NERDTreeShowHidden=1
        let NERDTreeKeepTreeInNewTab=1
        let g:nerdtree_tabs_open_on_gui_startup=0
    " }
    " Ranger {
        function! RangeChooser()
            let temp = tempname()
            " The option "--choosefiles" was added in ranger 1.5.1. Use the next line
            " with ranger 1.4.2 through 1.5.0 instead.
            "exec 'silent !ranger --choosefile=' . shellescape(temp)
            if has("gui_running")
                exec 'silent !xterm -e ranger --choosefiles=' . shellescape(temp)
            else
                exec 'silent !ranger --choosefiles=' . shellescape(temp)
            endif
            if !filereadable(temp)
                redraw!
                " Nothing to read.
                return
            endif
            let names = readfile(temp)
            if empty(names)
                redraw!
                " Nothing to open.
                return
            endif
            " Edit the first item.
            exec 'edit ' . fnameescape(names[0])
            " Add any remaning items to the arg list/buffer list.
            for name in names[1:]
                exec 'argadd ' . fnameescape(name)
            endfor
            redraw!
        endfunction
        command! -bar RangerChooser call RangeChooser()
        nnoremap <leader>r :<C-U>RangerChooser<CR>

    " }
    " vim-airline {
        if isdirectory(expand("~/.vim/bundle/vim-airline-themes/"))
            let g:airline_powerline_fonts = 1
            let g:airline_theme = 'gruvbox'
            "let g:airline_left_sep='›'  " Slightly fancier than '>'
            "let g:airline_right_sep='‹' " Slightly fancier than '<'
            let g:indent_guides_enable_on_vim_startup = 0
            let g:airline#extensions#tabline#enabled = 1
            "" Show just the filename
            let g:airline#extensions#tabline#fnamemod = ':t'
            let g:airline#extensions#bufferline#enabled = 0
        endif
    " }
    " delimitMate {
        let delimitMate_expand_cr = 2
        let delimitMate_jump_expansion = 1
    " }
    " Surround {
            let g:surround_indent = 1
    " }
    " Tabularize {
        if isdirectory(expand("~/.vim/bundle/tabular"))
            nmap <Leader>a& :Tabularize /&<CR>
            vmap <Leader>a& :Tabularize /&<CR>
            nmap <Leader>a= :Tabularize /^[^=]*\zs=<CR>
            vmap <Leader>a= :Tabularize /^[^=]*\zs=<CR>
            nmap <Leader>a=> :Tabularize /=><CR>
            vmap <Leader>a=> :Tabularize /=><CR>
            nmap <Leader>a: :Tabularize /:<CR>
            vmap <Leader>a: :Tabularize /:<CR>
            nmap <Leader>a:: :Tabularize /:\zs<CR>
            vmap <Leader>a:: :Tabularize /:\zs<CR>
            nmap <Leader>a, :Tabularize /,<CR>
            vmap <Leader>a, :Tabularize /,<CR>
            nmap <Leader>a,, :Tabularize /,\zs<CR>
            vmap <Leader>a,, :Tabularize /,\zs<CR>
            nmap <Leader>a<Bar> :Tabularize /<Bar><CR>
            vmap <Leader>a<Bar> :Tabularize /<Bar><CR>
        endif
    " }
    " UltiSnips{
            let g:UltiSnipsExpandTrigger="<leader><tab>"
            let g:UltiSnipsJumpForwardTrigger="<c-n>"
            let g:UltiSnipsJumpBackwardTrigger="<c-p>"
            let g:UltiSnipsEditSplit="vertical"
    " }
    " UndoTree{
        if isdirectory(expand("~/.vim/bundle/undotree/"))
            nnoremap <leader>u :UndotreeToggle<cr>
            let g:undotree_SetFocusWhenToggle=1
        endif
    " }
    " Ctags {
        set tags=./tags;/,~/.vimtags

        " Make tags placed in .git/tags file available in all levels of a repository
        let gitroot = substitute(system('git rev-parse --show-toplevel'), '[\n\r]', '', 'g')
        if gitroot != ''
            let &tags = &tags . ',' . gitroot . '/.git/tags'
        endif
    " }
    " Vim multiple cursors{
        let g:multi_cursor_use_default_mapping=0
        let g:multi_cursor_next_key='<C-d>'
        let g:multi_cursor_prev_key='<C-p>'
        let g:multi_cursor_skip_key='<C-x>'
        let g:multi_cursor_quit_key='<Esc>'
    " }
    " TableMode{
        let g:table_mode_corner_corner="+"
        let g:table_mode_header_fillchar="="
    " }
" }
" Functions {

    " Initialize directories {
    function! InitializeDirectories()
        let parent = $HOME
        let prefix = 'vim'
        let dir_list = {
                    \ 'backup': 'backupdir',
                    \ 'views': 'viewdir',
                    \ 'swap': 'directory' }

        if has('persistent_undo')
            let dir_list['undo'] = 'undodir'
        endif

        let common_dir = parent . '/.' . prefix

        for [dirname, settingname] in items(dir_list)
            let directory = common_dir . dirname . '/'
            if exists("*mkdir")
                if !isdirectory(directory)
                    call mkdir(directory)
                endif
            endif
            if !isdirectory(directory)
                echo "Warning: Unable to create backup directory: " . directory
                echo "Try: mkdir -p " . directory
            else
                let directory = substitute(directory, " ", "\\\\ ", "g")
                exec "set " . settingname . "=" . directory
            endif
        endfor
    endfunction
    call InitializeDirectories()
    " }

    " Strip whitespace {
    function! StripTrailingWhitespace()
        " Preparation: save last search, and cursor position.
        let _s=@/
        let l = line(".")
        let c = col(".")
        %s/\s\+$//e
        " clean up: restore previous search history, and cursor position
        let @/=_s
        call cursor(l, c)
    endfunction
    " }

" }

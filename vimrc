" vim: set sw=4 ts=4 sts=4 et tw=78 foldmarker={,} foldlevel=0 foldmethod=marker :

" Plug {

    call plug#begin('~/.vim/plugged')

    Plug 'morhetz/gruvbox'                  " Colorscheme

    Plug 'easymotion/vim-easymotion'        " Easy move inside vim
    Plug 'christoomey/vim-tmux-navigator'   " Seamless navigation between tmux panes and vim splits
    Plug 'terryma/vim-multiple-cursors'     " True Sublime Text style multiple selections for Vim

    Plug 'jiangmiao/auto-pairs'             " Auto-completion for quotes, parens, brackets, etc
    " Plug 'scrooloose/nerdcommenter'         " Comment functions so powerful—no comment necessary.
    Plug 'tpope/vim-commentary'             " Comment functions so powerful—no comment necessary.
    Plug 'tpope/vim-surround'               " Easy mapping to change brakets, parentheses, etc.
    Plug 'junegunn/vim-easy-align'          " A simple, easy-to-use Vim alignment plugin.

    Plug 'tpope/vim-fugitive'               " Git wrapper so awesome, it should be illegal
    Plug 'airblade/vim-gitgutter'           " Git diff on left sidebar

    Plug 'mbbill/undotree'                  " Left bar with undo tree
    Plug 'majutsushi/tagbar'                " Displays tags in right sidebar
    Plug 'scrooloose/nerdtree'

    Plug 'SirVer/ultisnips'                 " Snippets engine
    Plug 'honza/vim-snippets'               " Snippets catalog
    Plug 'ervandew/supertab'                " Tab completion

    Plug 'ctrlpvim/ctrlp.vim'               " File fuzzy finding
    Plug 'junegunn/fzf', { 'dir': '~/.fzf', 'do': './install --all' }
    Plug 'junegunn/fzf.vim'

    Plug 'vim-scripts/DrawIt'               " Vim draw draw lines left, right, up, down, boxes, etc
    Plug 'e0d1n/markersyntax'
    Plug 'w0rp/ale'
    Plug 'tomasiser/vim-code-dark'
    Plug 'dracula/vim'
    Plug 'tomlion/vim-solidity'
    Plug 'joshdick/onedark'

    call plug#end()

" }

" General {

    set background=dark                 " Assume a dark background
    set t_Co=256                        " Set terminal 256 color
    filetype plugin indent on           " Automatically detect file types.
    syntax on                           " Syntax highlighting
    set mousehide                       " Hide the mouse cursor while typing
    autocmd VimEnter * set nospell      " No spell check
    scriptencoding utf-8                " UTF-8 as default encoding

    " set clipboard=unnamed               " System clipboard

    " Always switch to the current file directory
    autocmd BufEnter * if bufname("") !~ "^\[A-Za-z0-9\]*://" | lcd %:p:h | endif

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

    autocmd WinEnter * call s:CloseIfOnlyNerdTreeLeft()

    set autowrite                       " Automatically write a file when leaving a modified buffer
    set shortmess+=filmnrxoOtT          " Abbrev. of messages (avoids 'hit enter')
    set viewoptions=folds,options,cursor,unix,slash " Better Unix / Windows compatibility
    set virtualedit=onemore             " Allow for cursor beyond last character
    set history=1000                    " Store a ton of history (default is 20)
    set timeoutlen=500                  " Time to wait for end of command
    set hidden                          " Allow buffer switching without saving
    set iskeyword-=.                    " '.' is an end of word designator
    set iskeyword-=#                    " '#' is an end of word designator
    set iskeyword-=-                    " '-' is an end of word designator

    set backup                          " Backups are nice ...
    set backupdir=~/.vim/backup          " Backups dir
    set directory=~/.vim/swap            " Swap dir
    set undodir=~/.vim/undo              " Undo dir
    set undofile                        " So is persistent undo ...
    set undolevels=1000                 " Maximum number of changes that can be undone
    set undoreload=10000                " Maximum number lines to save for undo on a buffer reload

    set ttyfast                         " Increase vim speed on a tty screen
    set lazyredraw                      " Buffer screen update, speedup scrolling and macro usage
" }

" Vim UI {

    " set termguicolors                   " Enable true color support
    if filereadable(expand("$HOME/.vim/plugged/onedark.vim/autoload/onedark.vim"))
        colorscheme onedark
    endif

    set tabpagemax=15                   " Only show 15 tabs
    set showmode                        " Display the current mode

    set cursorline                      " Highlight current line

    highlight clear SignColumn          " SignColumn (left) should match background
    highlight clear LineNr              " Current line number row will have same background color in relative mode

    set ruler                           " Show the ruler
    set rulerformat=%30(%=\:b%n%y%m%r%w\ %l,%c%V\ %P%) " A ruler on steroids
    set showcmd                         " Show partial commands in status line and
                                        " Selected characters/lines in visual mode

    set laststatus=2                        " To always display status bar

    " Broken down into easily includeable segments

    set statusline=%<%f\                    " Filename
    set statusline+=%w%h%m%r                " Options
    set statusline+=\ [%{&ff}/%Y]           " Filetype
    set statusline+=\ [%{getcwd()}]         " Current dir
    set statusline+=%=%-14.(%l,%c%V%)\ %p%% " Right aligned file nav info

    set backspace=indent,eol,start      " Backspace for dummies
    set linespace=0                     " No extra spaces between rows
    set number                          " Line numbers on
    " set relativenumber                  " Relative numbers on
    set showmatch                       " Show matching brackets/parenthesis
    set incsearch                       " Find as you type search
    set hlsearch                        " Highlight search terms
    set winminheight=0                  " Windows can be 0 line high
    " set selection=exclusive             " Selection match what you see
    set wildmenu                        " Show list instead of just completing commands
    set wildmode=list:longest,full      " Command <Tab> completion, list matches, then longest common part, then all.
    set whichwrap=b,s,h,l,<,>,[,]       " Backspace and cursor keys wrap too
    " set scrolljump=5                    " Lines to scroll when cursor leaves screen
    set scrolloff=3                     " Minimum lines to keep above and below cursor
    set foldenable                      " Auto fold code
    set list
    set listchars=tab:›\ ,trail:•,extends:#,nbsp:. " Highlight problematic whitespace

    set guioptions-=r                   " gui scrollbar
    set guioptions-=L                   " gui left scrollbar


" }

" Formatting {

    " if has("autocmd")
    "   " Highlight TODO, FIXME, NOTE, etc.
    "   if v:version > 701
    "     autocmd Syntax * call matchadd('Todo',  '\W\zs\(TODO\|FIXME\|CHANGED\|XXX\|BUG\|HACK\)')
    "     autocmd Syntax * call matchadd('Debug', '\W\zs\(NOTE\|INFO\|IDEA\)')
    "   endif
    " endif

    " Strip whitespace {
        " http://stackoverflow.com/questions/356126/how-can-you-automatically-remove-trailing-whitespace-in-vim

        function! StripTrailingWhitespaces()
            let _s=@/
            let l = line(".")
            let c = col(".")
            %s/\s\+$//e
            let @/=_s
            call cursor(l, c)
        endfun
    " }

    set nowrap                          " Do not wrap long lines
    set autoindent                      " Indent at the same level of the previous line
    set shiftwidth=4                    " Use indents of 4 spaces
    set expandtab                       " Tabs are spaces, not tabs
    set tabstop=4                       " An indentation every four columns
    set softtabstop=4                   " Let backspace delete indent
    set nojoinspaces                    " Prevents inserting two spaces after punctuation on a join (J)
    set splitright                      " Puts new vsplit windows to the right of the current
    set splitbelow                      " Puts new split windows to the bottom of the current

    set pastetoggle=<F2>                " pastetoggle (sane indentation on pastes)
    nnoremap <leader>p p`[v`]=          " Reindent pasted text with p key alternative (sickill/vim-pasta)

    " Remove trailings manually like StripTrailingWhitespaces()
    nnoremap <silent> <F5> :let _s=@/<Bar>:%s/\s\+$//e<Bar>:let @/=_s<Bar>:nohl<CR>

    " Remove Trailing whitespaces on save
    autocmd BufWritePre * :call StripTrailingWhitespaces()

" }

" Key Mappings {

    " Remap our leader key
    let mapleader = ','

    " Faster switch between split windows
    map <C-j> <C-w>j<C-w>_
    map <C-k> <C-w>k<C-w>_
    map <C-l> <C-w>l<C-w>_
    map <C-h> <C-w>h<C-w>_

    " Wrapped lines goes down/up to next row, rather than next line in file.
    noremap j gj
    noremap k gk

    " Correct most common errors while typing a command
    command! -bang -nargs=* -complete=file E e<bang> <args>
    command! -bang -nargs=* -complete=file W w<bang> <args>
    command! -bang -nargs=* -complete=file Wq wq<bang> <args>
    command! -bang -nargs=* -complete=file WQ wq<bang> <args>
    command! -bang Wa wa<bang>
    command! -bang WA wa<bang>
    command! -bang Q q<bang>
    command! -bang QA qa<bang>
    command! -bang Qa qa<bang>

    " Yank full line
    nnoremap Y yy

    " Clear search selection
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
    nmap <leader>ff [I:let nr = input("Which one: ")<Bar>exe "normal " . nr ."[\t"<CR>

    " Easier horizontal scrolling
    map zl zL
    map zh zH

    " Easier buffer change
    map gn :bn<cr>
    map gp :bp<cr>
    map <leader>d :bd<cr>

    " Changed base command to work with windows
    nnoremap <leader>w <c-w>

    " Fast save and exit
    map <leader>s :w<cr>
    map <leader>q :q<cr>
    map <leader>wq :wq<cr>

    nnoremap <C-a> _
    nnoremap <C-e> <End>

" }

" Plugins {

    " vim-airline {
        " let g:airline_left_sep='›'  " Slightly fancier than '>'
        " let g:airline_right_sep='‹' " Slightly fancier than '<'

        " let g:airline_powerline_fonts = 1
        " let g:airline_theme = 'gruvbox'

        " let g:indent_guides_enable_on_vim_startup = 0
        " let g:airline#extensions#tabline#enabled = 1
        "" Show just the filename
        " let g:airline#extensions#tabline#fnamemod = ':t'
        " let g:airline#extensions#bufferline#enabled = 0

    " }

    " NerdTree {
        map <silent> <leader>e :NERDTreeToggle<CR>

        " let NERDTreeShowBookmarks=1
        let NERDTreeIgnore=['\.py[cd]$', '\~$', '\.swo$', '\.swp$', '^\.git$', '^\.hg$', '^\.svn$', '\.bzr$','\.DS_Store']
        " Close all open buffers on entering a window if the only
        " buffer that's left is the NERDTree buffer
        function! s:CloseIfOnlyNerdTreeLeft()
          if exists("t:NERDTreeBufName")
            if bufwinnr(t:NERDTreeBufName) != -1
              if winnr("$") == 1
                q
              endif
            endif
          endif
        endfunction
        " let NERDTreeChDirMode=0
        " let NERDTreeQuitOnOpen=1
        " let NERDTreeMouseMode=2
        " let NERDTreeShowHidden=1
        " let NERDTreeKeepTreeInNewTab=1
        " let g:nerdtree_tabs_open_on_gui_startup=0
    " }

    " auto-pairs {

        " Shortcut to jump out of the pair
        let g:AutoPairsShortcutJump = '<S-Tab>'

    " }

    " UndoTree {

        nnoremap <silent> <leader>u :UndotreeToggle<cr>
        let g:undotree_SetFocusWhenToggle=1

    " }

    " YouCompleteMe {

        " let g:ycm_global_ycm_extra_conf = '~/.ycm_extra_conf.py'

        " " make YCM compatible with UltiSnips (using supertab)
        " let g:ycm_key_list_select_completion = ['<C-n>', '<Down>']
        " let g:ycm_key_list_previous_completion = ['<C-p>', '<Up>']
        " let g:SuperTabDefaultCompletionType = '<C-n>'

        " let g:ycm_collect_identifiers_from_tags_files = 1

        " let g:ycm_error_symbol = '✘'
        " let g:ycm_warning_symbol = '⚠️'

    " }

    " UltiSnips {

        " better key bindings for UltiSnipsExpandTrigger
        let g:UltiSnipsExpandTrigger = "<tab>"
        let g:UltiSnipsJumpForwardTrigger = "<tab>"
        let g:UltiSnipsJumpBackwardTrigger = "<s-tab>"

    " }

    " Nerdcommenter {

        " Add spaces after comment delimiters by default
        " let g:NERDSpaceDelims = 1
        " Enable trimming of trailing whitespace when uncommenting
        " let g:NERDTrimTrailingWhitespace = 1
        " Align line-wise comment delimiters flush left instead of following
        " code indentation
        " let g:NERDDefaultAlign = 'left'

    " }

    " Vim-multiple-cursors{

        let g:multi_cursor_use_default_mapping=0
        let g:multi_cursor_next_key='<C-d>'               " Mapped like sublime key
        let g:multi_cursor_prev_key='<C-p>'               " Default
        let g:multi_cursor_skip_key='<C-x>'               " Default
        let g:multi_cursor_quit_key='<C-c>'               " Exit mode key, It doesn't always work
        nnoremap <silent> <C-c> :call multiple_cursors#quit()<CR>  " Faster mode exit

    " }

    " TagBar {
        nnoremap <silent> <leader>t :TagbarToggle<CR>
        let g:tagbar_autofocus = 1
        let g:tagbar_autoclose = 1
    "}

    " Surround {
        let g:surround_indent = 1
    " }

    " Ctrl-p {
        nnoremap <silent> <leader>b :CtrlPBuffer<cr>
    " }

    " FZF {
        nnoremap <silent> <leader>f :FZF -m<cr>
    " }

    " vim-easy-align {
        " Start interactive EasyAlign in visual mode (e.g. vipga)
        xmap <Leader>a <Plug>(EasyAlign)

        " Start interactive EasyAlign for a motion/text object (e.g. gaip)
        nmap <Leader>a <Plug>(EasyAlign)
    " }

    " ALE {
        " Run on save
        let g:ale_lint_on_text_changed = 'never'
        " if you don't want linters to run on opening a file
        let g:ale_lint_on_enter = 0
    " }
" }

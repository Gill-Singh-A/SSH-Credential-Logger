#! /bin/bash

SCRIPT_PATH=$(realpath "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

alias ssh="$SCRIPT_DIR/main.py ssh 2>/dev/null"
alias sftp="$SCRIPT_DIR/main.py sftp 2>/dev/null"
alias scp="$SCRIPT_DIR/main.py scp 2>/dev/null"
#! /bin/bash

SCRIPT_PATH=$(realpath "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

alias ssh="$SCRIPT_DIR/main.py ssh"
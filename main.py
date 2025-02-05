#! /usr/bin/env python3

from modified_paramiko_pkey import KeyDecrpter

import sys, paramiko
from getpass import getpass

if __name__ == "__main__":
    arguments = sys.argv[1:]
    user, host, port, private_key_file = None, None, 22, None
    if "-p" in arguments:
        port = arguments[arguments.index("-p")+1]
    for argument in arguments:
        if '@' in argument:
            user, host = argument.split('@')
    if "-i" in arguments:
        private_key_file = arguments[arguments.index("-i")+1]
        with open(private_key_file, 'r') as file:
            private_key_file_lines = file.readlines()
#! /usr/bin/env python3

from modified_paramiko_pkey import KeyDecrpter

import sys, paramiko
from getpass import getpass

def check_ssh(target, target_user, target_password=None, target_port=22, private_key_file_path=None, private_key_passphrase=None):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        private_key = paramiko.RSAKey.from_private_key_file(private_key_file_path, private_key_passphrase) if private_key_file_path != None else None
        ssh_client.connect(target, port=target_port, username=target_user, pkey=private_key, look_for_keys=False, allow_agent=False) if private_key != None else ssh_client.connect(target, port=target_port, username=target_user, password=target_password, look_for_keys=False, allow_agent=False)
        ssh_client.close()
        return True
    except Exception as error:
        return False

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
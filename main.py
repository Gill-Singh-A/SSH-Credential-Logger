#! /usr/bin/env python3

import os, sys, paramiko, subprocess
from getpass import getpass

program_name = "sshpass"

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
        port = int(arguments[arguments.index("-p")+1])
    for argument in arguments:
        if '@' in argument:
            user, host = argument.split('@')
    if "-i" in arguments:
        private_key_file = arguments[arguments.index("-i")+1]
        try:
            with open(private_key_file, 'r') as file:
                private_key_file_lines = file.readlines()
        except FileNotFoundError:
            print(f"Warning: Identity file {private_key_file} not accessible: No such file or directory.")
            print(f"{user}@{host}: Permission denied (publickey).")
            exit(0)
    if not private_key_file:
        password = getpass(f"{user}@{host}'s password: ")
        while not check_ssh(host, user, password, port):
            print("Permission denied, please try again.")
            password = getpass(f"{user}@{host}'s password: ")
        with open("credentials", 'a') as file:
            file.write(f"SSH,{host},{port},{user},{password}\n")
        sshpass_arguments = [program_name, '-p', password]
        sshpass_arguments.extend(arguments)
        os.execvp(program_name, sshpass_arguments)
    else:
        passphrase = getpass(f"Enter passphrase for key '{private_key_file}': ")
        while not check_ssh(host, user, target_port=port, private_key_file_path=private_key_file, private_key_passphrase=passphrase):
            passphrase = getpass(f"Enter passphrase for key '{private_key_file}': ")
        with open("credentials", 'a') as file:
            file.write(f"SSH,{host},{port},{user},{private_key_file},{passphrase}\n")
        os.execvp(arguments[0], arguments)
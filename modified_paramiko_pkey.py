# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

import base64
from base64 import decodebytes
from binascii import unhexlify
from hashlib import md5
import re
import struct

import bcrypt

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher

from paramiko import util
from paramiko.util import b
from paramiko.ssh_exception import SSHException, PasswordRequiredException


OPENSSH_AUTH_MAGIC = b"openssh-key-v1\x00"


def _unpad_openssh(data):
    # At the moment, this is only used for unpadding private keys on disk. This
    # really ought to be made constant time (possibly by upstreaming this logic
    # into pyca/cryptography).
    padding_length = data[-1]
    if 0x20 <= padding_length < 0x7F:
        return data  # no padding, last byte part comment (printable ascii)
    if padding_length > 15:
        raise SSHException("Invalid key")
    for i in range(padding_length):
        if data[i - padding_length] != i + 1:
            raise SSHException("Invalid key")
    return data[:-padding_length]


class KeyDecrpter:

    # known encryption types for private key files:
    _CIPHER_TABLE = {
        "AES-128-CBC": {
            "cipher": algorithms.AES,
            "keysize": 16,
            "blocksize": 16,
            "mode": modes.CBC,
        },
        "AES-256-CBC": {
            "cipher": algorithms.AES,
            "keysize": 32,
            "blocksize": 16,
            "mode": modes.CBC,
        },
        "DES-EDE3-CBC": {
            "cipher": algorithms.TripleDES,
            "keysize": 24,
            "blocksize": 8,
            "mode": modes.CBC,
        },
    }
    _PRIVATE_KEY_FORMAT_ORIGINAL = 1
    _PRIVATE_KEY_FORMAT_OPENSSH = 2
    BEGIN_TAG = re.compile(
        r"^-{5}BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-{5}\s*$"
    )
    END_TAG = re.compile(r"^-{5}END (RSA|DSA|EC|OPENSSH) PRIVATE KEY-{5}\s*$")

    def __init__(self, lines, password=None):
        tag = "RSA"
        if not lines:
            raise SSHException("no lines in {} private key file".format(tag))

        # find the BEGIN tag
        start = 0
        m = KeyDecrpter.BEGIN_TAG.match(lines[start])
        line_range = len(lines) - 1
        while start < line_range and not m:
            start += 1
            m = KeyDecrpter.BEGIN_TAG.match(lines[start])
        start += 1
        keytype = m.group(1) if m else None
        if start >= len(lines) or keytype is None:
            raise SSHException("not a valid {} private key file".format(tag))

        # find the END tag
        end = start
        m = KeyDecrpter.END_TAG.match(lines[end])
        while end < line_range and not m:
            end += 1
            m = KeyDecrpter.END_TAG.match(lines[end])

        if keytype == tag:
            data = self._read_private_key_pem(lines, end, password)
            pkformat = self._PRIVATE_KEY_FORMAT_ORIGINAL
        elif keytype == "OPENSSH":
            data = self._read_private_key_openssh(lines[start:end], password)
            pkformat = self._PRIVATE_KEY_FORMAT_OPENSSH
        else:
            raise SSHException(
                "encountered {} key, expected {} key".format(keytype, tag)
            )

    def _read_private_key_pem(self, lines, end, password):
        start = 0
        # parse any headers first
        headers = {}
        start += 1
        while start < len(lines):
            line = lines[start].split(": ")
            if len(line) == 1:
                break
            headers[line[0].lower()] = line[1].strip()
            start += 1
        # if we trudged to the end of the file, just try to cope.
        try:
            data = decodebytes(b("".join(lines[start:end])))
        except base64.binascii.Error as e:
            raise SSHException("base64 decoding error: {}".format(e))
        if "proc-type" not in headers:
            # unencryped: done
            return data
        # encrypted keyfile: will need a password
        proc_type = headers["proc-type"]
        if proc_type != "4,ENCRYPTED":
            raise SSHException(
                'Unknown private key structure "{}"'.format(proc_type)
            )
        try:
            encryption_type, saltstr = headers["dek-info"].split(",")
        except:
            raise SSHException("Can't parse DEK-info in private key file")
        if encryption_type not in self._CIPHER_TABLE:
            raise SSHException(
                'Unknown private key cipher "{}"'.format(encryption_type)
            )
        # if no password was passed in,
        # raise an exception pointing out that we need one
        if password is None:
            raise PasswordRequiredException("Private key file is encrypted")
        cipher = self._CIPHER_TABLE[encryption_type]["cipher"]
        keysize = self._CIPHER_TABLE[encryption_type]["keysize"]
        mode = self._CIPHER_TABLE[encryption_type]["mode"]
        salt = unhexlify(b(saltstr))
        key = util.generate_key_bytes(md5, salt, password, keysize)
        decryptor = Cipher(
            cipher(key), mode(salt), backend=default_backend()
        ).decryptor()
        return decryptor.update(data) + decryptor.finalize()

    def _read_private_key_openssh(self, lines, password):
        """
        Read the new OpenSSH SSH2 private key format available
        since OpenSSH version 6.5
        Reference:
        https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
        """
        try:
            data = decodebytes(b("".join(lines)))
        except base64.binascii.Error as e:
            raise SSHException("base64 decoding error: {}".format(e))

        # read data struct
        auth_magic = data[:15]
        if auth_magic != OPENSSH_AUTH_MAGIC:
            raise SSHException("unexpected OpenSSH key header encountered")

        cstruct = self._uint32_cstruct_unpack(data[15:], "sssur")
        cipher, kdfname, kdf_options, num_pubkeys, remainder = cstruct
        # For now, just support 1 key.
        if num_pubkeys > 1:
            raise SSHException(
                "unsupported: private keyfile has multiple keys"
            )
        pubkey, privkey_blob = self._uint32_cstruct_unpack(remainder, "ss")

        if kdfname == b("bcrypt"):
            if cipher == b("aes256-cbc"):
                mode = modes.CBC
            elif cipher == b("aes256-ctr"):
                mode = modes.CTR
            else:
                raise SSHException(
                    "unknown cipher `{}` used in private key file".format(
                        cipher.decode("utf-8")
                    )
                )
            # Encrypted private key.
            # If no password was passed in, raise an exception pointing
            # out that we need one
            if password is None:
                raise PasswordRequiredException(
                    "private key file is encrypted"
                )

            # Unpack salt and rounds from kdfoptions
            salt, rounds = self._uint32_cstruct_unpack(kdf_options, "su")

            # run bcrypt kdf to derive key and iv/nonce (32 + 16 bytes)
            key_iv = bcrypt.kdf(
                b(password),
                b(salt),
                48,
                rounds,
                # We can't control how many rounds are on disk, so no sense
                # warning about it.
                ignore_few_rounds=True,
            )
            key = key_iv[:32]
            iv = key_iv[32:]

            # decrypt private key blob
            decryptor = Cipher(
                algorithms.AES(key), mode(iv), default_backend()
            ).decryptor()
            decrypted_privkey = decryptor.update(privkey_blob)
            decrypted_privkey += decryptor.finalize()
        elif cipher == b("none") and kdfname == b("none"):
            # Unencrypted private key
            decrypted_privkey = privkey_blob
        else:
            raise SSHException(
                "unknown cipher or kdf used in private key file"
            )

        # Unpack private key and verify checkints
        cstruct = self._uint32_cstruct_unpack(decrypted_privkey, "uusr")
        checkint1, checkint2, keytype, keydata = cstruct

        if checkint1 != checkint2:
            raise SSHException(
                "OpenSSH private key file checkints do not match"
            )

        return _unpad_openssh(keydata)

    def _uint32_cstruct_unpack(self, data, strformat):
        """
        Used to read new OpenSSH private key format.
        Unpacks a c data structure containing a mix of 32-bit uints and
        variable length strings prefixed by 32-bit uint size field,
        according to the specified format. Returns the unpacked vars
        in a tuple.
        Format strings:
          s - denotes a string
          i - denotes a long integer, encoded as a byte string
          u - denotes a 32-bit unsigned integer
          r - the remainder of the input string, returned as a string
        """
        arr = []
        idx = 0
        try:
            for f in strformat:
                if f == "s":
                    # string
                    s_size = struct.unpack(">L", data[idx : idx + 4])[0]
                    idx += 4
                    s = data[idx : idx + s_size]
                    idx += s_size
                    arr.append(s)
                if f == "i":
                    # long integer
                    s_size = struct.unpack(">L", data[idx : idx + 4])[0]
                    idx += 4
                    s = data[idx : idx + s_size]
                    idx += s_size
                    i = util.inflate_long(s, True)
                    arr.append(i)
                elif f == "u":
                    # 32-bit unsigned int
                    u = struct.unpack(">L", data[idx : idx + 4])[0]
                    idx += 4
                    arr.append(u)
                elif f == "r":
                    # remainder as string
                    s = data[idx:]
                    arr.append(s)
                    break
        except Exception as e:
            # PKey-consuming code frequently wants to save-and-skip-over issues
            # with loading keys, and uses SSHException as the (really friggin
            # awful) signal for this. So for now...we do this.
            raise SSHException(str(e))
        return tuple(arr)
#!/usr/bin/env python3

import base64
import sys
import os
import getpass

from construct import (
    this,
    Struct,
    Int32ub,
    PascalString,
    GreedyBytes,
    Switch,
    BytesInteger,
    NullTerminated,
    Const,
    Bytes,
    Array,
    FixedSized,
)

from Crypto.Cipher import AES
from Crypto.Util import Counter

import bcrypt


def derive_key_and_iv(passphrase, salt, rounds):
    key_len = 32
    iv_len = 16
    key = bcrypt.kdf(passphrase, salt, key_len + iv_len, rounds)
    return key[:key_len], key[key_len:key_len+iv_len]

def decrypt_aes_ctr(key, iv, data):
    ctr = Counter.new(
        AES.block_size * 8,
        initial_value=int.from_bytes(iv, 'big')
    )
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return aes.decrypt(data)

def decrypt_private_keys(data, passphrase, salt, rounds):
    # https://github.com/openssh/openssh-portable/blob/ef5916b8acd9b1d2f39fad4951dae03b00dbe390/sshkey.c#L3887-L4013
    # TODO other than aes256-ctr and bcrypt
    key, iv = derive_key_and_iv(passphrase.encode('utf-8'), salt, rounds)
    return decrypt_aes_ctr(key, iv, data)

def read_ssh_private_key_bytes(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    data_lines = []
    for line in data.splitlines():
        if line.startswith(b'-----'):
            continue
        data_lines.append(line)
    return base64.b64decode(b''.join(data_lines))

def decode_ssh_private_key_bytes(data):
    # https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD
    # https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04
    # https://dnaeon.github.io/openssh-private-key-binary-format/

    # definitions

    # https://github.com/openssh/openssh-portable/blob/d902d728dfd81622454260e23bc09d5e5a9a795e/cipher.c#L67-L113
    cipher_block_sizes = {
        'none': 8,
        'aes256-ctr': 16,
    }

    # common formats

    MPInt = Struct(
        'size' / Int32ub,
        'value' / BytesInteger(this.size)
    )

    # private key encryption options format

    SSHKDFOptions = Struct(
        'salt' / Struct(
            'size' / Int32ub,
            'value' / Bytes(this.size),
        ),
        'rounds' / Int32ub,
    )

    SSHPrivkeyCryptOptions = Struct(
        'ciphername' / PascalString(Int32ub, 'ascii'),
        'kdfname' / PascalString(Int32ub, 'ascii'),
        'kdfoptions' / Struct(
            'size' / Int32ub,
            'value' / FixedSized(
                this.size,
                Switch(this._.ciphername, {
                    'none': Struct(),
                    'aes256-ctr': SSHKDFOptions
                }),
            ),
        ),
    )

    # embedded public key format

    SSHRSAPubkey = Struct(
        'e' / MPInt,
        'n' / MPInt,
    )

    SSHECDSAPubkey = Struct(
        # TODO
    )

    SSHed25519Pubkey = Struct(
        # TODO
    )

    SSHDSSPubkey = Struct(
        # TODO
    )

    SSHPubkeyFile = Struct(
        'type' / PascalString(Int32ub, 'ascii'),
        'key' / Switch(this.type, {
            'ssh-rsa': SSHRSAPubkey,
            'ecdsa-sha2-nistp256': SSHECDSAPubkey,
            'ssh-ed25519': SSHed25519Pubkey,
            'ssh-dss': SSHDSSPubkey,
        }),
        # 'rest' / GreedyBytes
    )

    SSHEmbeddedPubkeys = Struct(
        'size' / Int32ub,
        'values' / Array(
            this.size,
            Struct(
                'size' / Int32ub,
                'value' / FixedSized(this.size, SSHPubkeyFile)
            )
        ),
    )

    # private key format

    SSHRSAPrivkey = Struct(
        'n' / MPInt,
        'e' / MPInt,
        'd' / MPInt,
        'iqmp' / MPInt,
        'p' / MPInt,
        'q' / MPInt,
        'comment' / PascalString(Int32ub, 'ascii'),
        # whatever, it's always just one key anyway
        'pad' / GreedyBytes,
    )

    SSHECDSAPrivkey = Struct(
        # TODO
    )

    SSHed25519Privkey = Struct(
        # TODO
    )

    SSHDSSPrivkey = Struct(
        # TODO
    )

    SSHPrivkey = Struct(
        'type' / PascalString(Int32ub, 'ascii'),
        'key' / Switch(this.type, {
            'ssh-rsa': SSHRSAPrivkey,
            'ecdsa-sha2-nistp256': SSHECDSAPrivkey,
            'ssh-ed25519': SSHed25519Privkey,
            'ssh-dss': SSHDSSPrivkey,
        }),
    )

    def ssh_privkeys_struct(custom_size=None):
        if custom_size:
            size = custom_size
        else:
            size = this._._.pubkeys.size
        SSHPrivkeysUnencrypted = Struct(
            # TODO assert checkint1 == checkint2
            'checkint1' / Int32ub,
            'checkint2' / Int32ub,
            'privkeys' / Array(size, SSHPrivkey),
        )
        return SSHPrivkeysUnencrypted

    SSHPrivkeys = Struct(
        'size' / Int32ub,
        'value' / FixedSized(
            this.size,
            # _ means parent
            Switch(this._.cryptoptions.ciphername, {
                'none': ssh_privkeys_struct(),
                'aes256-ctr': GreedyBytes,
            }),
        )
    )

    # overall private key file format

    SSHPrivkeyFile = Struct(
        'magic' / NullTerminated(Const(b'openssh-key-v1')),
        'cryptoptions' / SSHPrivkeyCryptOptions,
        'pubkeys' / SSHEmbeddedPubkeys,
        'privkeys' / SSHPrivkeys,
        # 'rest' / GreedyBytes
    )

    parsed = SSHPrivkeyFile.parse(data)

    print(parsed)

    cryptopt = parsed.cryptoptions
    if cryptopt.ciphername == 'aes256-ctr' and cryptopt.kdfname == 'bcrypt':
        kdfopt = cryptopt.kdfoptions.value
        print('Decrypting SSH private keys')
        passphrase = getpass.getpass()
        plaintext = decrypt_private_keys(
            parsed.privkeys.value,
            passphrase,
            kdfopt.salt.value,
            kdfopt.rounds
        )
        private_keys_decrypted = ssh_privkeys_struct(1).parse(plaintext)
        print(private_keys_decrypted)

def write_stdout_bytes(data):
    with os.fdopen(sys.stdout.fileno(), 'wb', closefd=False) as stdout:
        stdout.write(data)
        stdout.flush()

def main():
    filename = sys.argv[1]
    data = read_ssh_private_key_bytes(filename)
    decode_ssh_private_key_bytes(data)
    # write_stdout_bytes(data)

if __name__ == '__main__':
    main()

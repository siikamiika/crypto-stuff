#!/usr/bin/env python3

import base64
import sys

from construct import (
    this,
    Struct,
    Int32ub,
    PascalString,
    GreedyBytes,
    Switch,
    BytesInteger,
)

def read_ssh_public_key_bytes(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    return base64.b64decode(data.split()[1])

def decode_ssh_public_key_bytes(data):
    Bignum = Struct(
        'size' / Int32ub,
        'value' / BytesInteger(lambda this: this.size)
    )

    ssh_pubkey_format = Struct(
        'key_name' / PascalString(Int32ub, 'ascii'),
        'key' / Switch(this.key_name, {
            'ssh-rsa': Struct(
                'e' / Bignum,
                'n' / Bignum,
            ),
            'ecdsa-sha2-nistp256': Struct(
                # TODO
            ),
            'ssh-ed25519': Struct(
                # TODO
            ),
            'ssh-dss': Struct(
                # TODO
            )
        }),
        'rest' / GreedyBytes
    )
    ssh_pubkey = ssh_pubkey_format.parse(data)
    if ssh_pubkey.key_name == 'ssh-rsa':
        k = ssh_pubkey.key
        print(f'e={k.e.value}, n={k.n.value}')

def main():
    filename = sys.argv[1]
    data = read_ssh_public_key_bytes(filename)
    decode_ssh_public_key_bytes(data)

if __name__ == '__main__':
    main()

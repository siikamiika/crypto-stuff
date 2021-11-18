#!/usr/bin/env python3

import base64
import sys
import os

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
    Bignum = Struct(
        'size' / Int32ub,
        'value' / BytesInteger(lambda this: this.size)
    )

    SSHPubkey = Struct(
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
        # 'rest' / GreedyBytes
    )

    # https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD
    # https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04

    SSHPrivkey = Struct(
        'magic' / NullTerminated(Const(b'openssh-key-v1')),
        'ciphername' / PascalString(Int32ub, 'ascii'),
        'kdfname' / PascalString(Int32ub, 'ascii'),
        'kdfoptions' / Struct(
            'size' / Int32ub,
            'value' / Bytes(this.size) # TODO parse
        ),
        'num_pubkeys' / Int32ub,
        'pubkeys' / Array(
            this.num_pubkeys,
            Struct(
                'size' / Int32ub,
                'pubkey' / FixedSized(this.size, SSHPubkey)
            )
        ),
        'privkeys' / Struct(
            'size' / Int32ub,
            'value' / FixedSized(
                this.size,
                # _ means parent
                Switch(this._.ciphername, {
                    'none': Struct(
                        # TODO assert checkint1 == checkint2
                        'checkint1' / Int32ub,
                        'checkint2' / Int32ub,
                        # TODO support multiple private keys
                        # is it the same amount as pubkeys?
                        'privkey_magic_size' / Int32ub,
                        'privkey_magic' / FixedSized(this.privkey_magic_size, GreedyBytes),
                        'n' / Bignum,
                        'e' / Bignum,
                        'd' / Bignum,
                        'iqmp' / Bignum,
                        'p' / Bignum,
                        'q' / Bignum,
                        'comment' / PascalString(Int32ub, 'ascii'),
                        # TODO not so greedy
                        'pad' / GreedyBytes,
                    ),
                    'aes256-ctr': GreedyBytes
                }),
            )
        ),
        # 'rest' / GreedyBytes
    )

    print(SSHPrivkey.parse(data))

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

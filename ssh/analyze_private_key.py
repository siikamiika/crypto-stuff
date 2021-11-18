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
        'pad' / Bytes(
            lambda this: (
                len(this._.type) + 4
                + sum(this[x].size for x in ['n', 'e', 'd', 'iqmp', 'p', 'q'])
                + len(this.comment) + 4
            ) % cipher_block_sizes[this._._._._.cryptoptions.ciphername]
        ),
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

    SSHPrivkeysUnencrypted = Struct(
        # TODO assert checkint1 == checkint2
        'checkint1' / Int32ub,
        'checkint2' / Int32ub,
        'privkeys' / Array(
            this._._.pubkeys.size,
            SSHPrivkey
        ),
    )

    SSHPrivkeys = Struct(
        'size' / Int32ub,
        'value' / FixedSized(
            this.size,
            # _ means parent
            Switch(this._.cryptoptions.ciphername, {
                'none': SSHPrivkeysUnencrypted,
                'aes256-ctr': GreedyBytes
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

    print(SSHPrivkeyFile.parse(data))

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

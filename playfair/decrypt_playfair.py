#!/usr/bin/env python3

class Playfair:
    def __init__(self, key):
        self._key = key

    def decrypt(self, ciphertext):
        i = 0
        out = []
        while True:
            chars = []
            if len(ciphertext) <= i:
                break
            while len(chars) < 2:
                if len(ciphertext) <= i:
                    char = ('Z', i)
                else:
                    char = (ciphertext[i].upper(), i)
                if 'A' <= char[0].upper() <= 'Z':
                    chars.append(char)
                else:
                    out.append(char)
                i += 1
            coord_a, coord_b = map(self._find_coord, chars)
            if coord_a[0] == coord_b[0]:
                out.append((
                    self._key[coord_a[0]][(coord_a[1] - 1) % 5],
                    chars[0][1]
                ))
                out.append((
                    self._key[coord_b[0]][(coord_b[1] - 1) % 5],
                    chars[1][1]
                ))
            elif coord_a[1] == coord_b[1]:
                out.append((
                    self._key[(coord_a[0] - 1) % 5][coord_a[1]],
                    chars[0][1]
                ))
                out.append((
                    self._key[(coord_b[0] - 1) % 5][coord_b[1]],
                    chars[1][1]
                ))
            else:
                out.append((
                    self._key[coord_a[0]][coord_b[1]],
                    chars[0][1]
                ))
                out.append((
                    self._key[coord_b[0]][coord_a[1]],
                    chars[1][1]
                ))
        return ''.join(map(lambda x: x[0], sorted(out, key=lambda x: x[1])))

    def _find_coord(self, char):
        char, i = char
        char = char.upper()
        if char == 'J':
            char = 'I'
        for y, row in enumerate(self._key):
            for x, char2 in enumerate(row):
                if char == char2:
                    return y, x
        raise Exception('oopsie woopsie')

ciphertext = 'asdfahdbgweywyenyw87wehnvcwc'

char_map = [
    'QWERT',
    'YUIOP',
    'ASDFG',
    'HKLZX',
    'CVBNM',
]

pf = Playfair(char_map)
print(pf.decrypt(ciphertext))

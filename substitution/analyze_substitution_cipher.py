#!/usr/bin/env python3

import sqlite3
import json

def substitution_independent_representation(text):
    mapping = {}
    out = []
    sub = ord('A')
    for char in text:
        if char not in mapping:
            mapping[char] = chr(sub)
            sub += 1
        out.append(mapping[char])
    return ''.join(out)

con = sqlite3.connect(':memory:')
cur = con.cursor()
cur.execute('''
    CREATE TABLE plaintext_substrings (
        substring TEXT UNIQUE,
        substitution_idx TEXT,
        amount INTEGER
    )
''')
cur.execute('CREATE INDEX plaintext_substring_idx ON plaintext_substrings(substring)')
cur.execute('CREATE INDEX plaintext_substitution_idx_idx ON plaintext_substrings(substitution_idx)')
cur.execute('''
    CREATE TABLE ciphertext_substrings (
        substring TEXT UNIQUE,
        substitution_idx TEXT,
        amount INTEGER
    )
''')
cur.execute('CREATE INDEX ciphertext_substring_idx ON ciphertext_substrings(substring)')
cur.execute('CREATE INDEX ciphertext_substitution_idx_idx ON ciphertext_substrings(substitution_idx)')
con.commit()

with open('./language_words.txt', 'r') as f:
    for word in f:
        word = word.strip().upper()
        for i in range(2, 12):
            if len(word) - i < 0:
                continue
            for j in range(0, len(word) - i + 1):
                substr = word[j:j+i]
                if ' ' in substr:
                    continue
                cur.execute(
                    '''
                    insert into plaintext_substrings (substring, substitution_idx, amount)
                    values (?, ?, 1)
                    on conflict (substring) do update set amount = amount + 1
                    ''',
                    [substr, substitution_independent_representation(substr)]
                )
con.commit()

with open('./ciphertext.txt', 'r') as f:
    ciphertext = f.read()

for i in range(2, 12):
    for j in range(0, len(ciphertext) - i + 1):
        substr = ciphertext[j:j+i]
        if ' ' in substr:
            continue
        cur.execute(
            '''
            insert into ciphertext_substrings (substring, substitution_idx, amount)
            values (?, ?, 1)
            on conflict (substring) do update set amount = amount + 1
            ''',
            [substr, substitution_independent_representation(substr)]
        )
con.commit()

substitutions = {}

for row in list(cur.execute('''
    select *
    from ciphertext_substrings
    where amount > 1
    order by length(substring) desc
''')):
    # substring TEXT UNIQUE,
    # substitution_idx TEXT,
    # amount INTEGER
    print(row)
    for row2 in cur.execute(
        '''
        select *
        from plaintext_substrings
        where substitution_idx = ?
        order by amount desc
        limit 1
        ''',
        [row[1]]
    ):
        print('   ', row2)
        for cc, pc in zip(row[0], row2[0]):
            if cc not in substitutions:
                invalid = False
                for v in substitutions.values():
                    if pc == v:
                        invalid = True
                        break
                if invalid:
                    continue
                substitutions[cc] = pc

with open('substitutions.json', 'w') as f:
    json.dump(substitutions, f, indent=4)

for char in ciphertext:
    print(substitutions.get(char) or char, end='')

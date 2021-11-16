import random
import math


# https://stackoverflow.com/a/568618/2444105
def gen_primes():
    """ Generate an infinite sequence of prime numbers.
    """
    # Maps composites to primes witnessing their compositeness.
    # This is memory efficient, as the sieve is not "run forward"
    # indefinitely, but only as long as required by the current
    # number being tested.
    #
    D = {}
    # The running integer that's checked for primeness
    q = 2
    while True:
        if q not in D:
            # q is a new prime.
            # Yield it and mark its first multiple that isn't
            # already marked in previous iterations
            yield q
            D[q * q] = [q]
        else:
            # q is composite. D[q] is the list of primes that
            # divide it. Since we've reached q, we no longer
            # need it in the map, but we'll mark the next
            # multiples of its witnesses to prepare for larger
            # numbers
            for p in D[q]:
                D.setdefault(p + q, []).append(p)
            del D[q]
        q += 1


class RSA:
    def __init__(self, p, q):
        (
            self._public_key,
            self._private_key
        ) = self._gen_keypair(p, q)

    def __repr__(self):
        return f'RSA(pubkey={self._public_key}, privkey={self._private_key})'

    def get_public_key(self):
        return self._public_key

    def get_private_key(self):
        return self._private_key

    def encrypt(self, data, public_key):
        e, n = public_key
        number = int.from_bytes(data, 'big')
        ciphertext = pow(number, e, n)
        return self._convert_number_bytes(ciphertext)

    def decrypt(self, data):
        d, n = self._private_key
        number = int.from_bytes(data, 'big')
        plaintext = pow(number, d, n)
        return self._convert_number_bytes(plaintext)

    def _convert_number_bytes(self, number):
        length = math.ceil(math.log2(number + 1) / 8)
        return number.to_bytes(length, 'big')

    def _gen_keypair(self, p, q):
        n = p * q
        # totient aka phi(n)
        totient = (p - 1) * (q - 1)
        e = self._choose_encryption_key(n, totient)
        # d * e % totient == 1
        d = pow(e, -1, totient)
        return (e, n), (d, n)

    def _choose_encryption_key(self, n, totient):
        while True:
            e = random.randrange(2, totient)
            # is coprime
            if self._gcd(e, totient) == 1:
                return e

    def _gcd(self, a, b):
        while b != 0:
            a, b = b, a % b
        return a


def main():
    primes = []
    for prime in gen_primes():
        if prime > 1000000:
            primes.append(prime)
        if prime > 2000000:
            break
    random.shuffle(primes)

    p_bob, q_bob = primes[0:2]
    print(f'Bob picks primes (p={p_bob}, q={q_bob})')
    bob_rsa = RSA(p_bob, q_bob)
    print(bob_rsa)

    p_alice, q_alice = primes[2:4]
    print(f'Alice picks primes (p={p_alice}, q={q_alice})')
    alice_rsa = RSA(p_alice, q_alice)
    print(alice_rsa)

    print()

    alice_pubkey = alice_rsa.get_public_key()
    print(f'Alice gives her public key {alice_pubkey} to Bob')

    bob_message = input('Bob, enter a message: ')
    bob_alice_ciphertext = bob_rsa.encrypt(
        bob_message.encode('utf-8'),
        alice_pubkey
    )
    print(f'Bob sends {bob_alice_ciphertext} to Alice')

    bob_alice_plaintext = alice_rsa.decrypt(bob_alice_ciphertext).decode('utf-8')
    print(f'Alice decrypts the ciphertext and receives "{bob_alice_plaintext}"')

main()

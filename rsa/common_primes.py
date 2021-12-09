import itertools
import gmpy2

primes = []
prev = 1
for _ in range(10):
    prev = gmpy2.next_prime(prev)
    primes.append(prev)

n_list = []
for p, q in itertools.combinations(primes, 2):
    n_list.append(p * q)


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

mapped_roots = {n: [] for n in n_list}
for a, b in itertools.combinations(n_list, 2):
    if (r := gcd(a, b)) > 1:
        for n in a, b:
            if r not in mapped_roots[n]:
                mapped_roots[n].append(r)
for n, roots in mapped_roots.items():
    if not roots:
        for n_, roots_ in mapped_roots.items():
            if n_ == n:
                continue
            for root in roots_:
                if n % root == 0:
                    roots.append(root)

for n, roots in mapped_roots.items():
    print(n, roots)

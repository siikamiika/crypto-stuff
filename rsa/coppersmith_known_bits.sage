# vi: ft=python
# type: ignore

# https://latticehacks.cr.yp.to/rsa.html
# with some additional comments and usability tweaks

import argparse

class partial_factoring:
    def __init__(self,N,a,X):
        self.N = N
        self.a = a
        self.X = X
        self.R = ZZ['x']
        x = self.R.0
        self.f = x+a

    # k is the multiplicity of the desired roots mod N
    # kd+t-1 is the degree of the polynomial that is produced
    def gen_lattice(self,t=1,k=1):
        dim = k+t
        A = matrix(IntegerRing(),dim,dim)
        x = self.R.0
        X = self.X

        monomial_list = [x^i for i in range(dim)]
        for i in range(k):
            g = self.f(X*x)^i*self.N^(k-i)
            A[i] = [g.monomial_coefficient(mon) for mon in monomial_list]
        for j in range(t):
            g = self.f(X*x)^k*(X*x)^j
            A[k+j] = [g.monomial_coefficient(mon) for mon in monomial_list]

        weights = [X^i for i in range(dim)]
        def getf(M,i):
            return sum(self.R(b/w)*mon for b,mon,w in zip(M[i],monomial_list,weights))
        return A,getf

    def solve(self,t=1,k=1):
        A,getf = self.gen_lattice(t,k)
        B = A.LLL()
        factors = []

        for r,multiplicity in getf(B,0).roots():
            if r not in ZZ:
                continue
            if gcd(Integer(self.f(r)),self.N) != 1:
                p = gcd(self.f(r),self.N)
                factors.append(p)
        return factors

def run(c, e, N, nlen, rlen, p_known, test):
    if test:
        base = randint(2 ^ (nlen // 2 - 1), 2 ^ (nlen // 2))
        _p = next_prime(base - randint(0, 2 ^ (rlen - 1)))
        _q = next_prime(base + randint(0, 2 ^ (rlen - 1)))
        N = _p * _q

    if not c:
        c = pow(int.from_bytes(b'ourhardworkbythesewordsguardedpleasedontsteal(c)applecomputerinc', 'big'), e, N)

    if not p_known:
        p_known = isqrt(N)

    # unknown bits
    X = 2 ^ rlen
    r = lift(mod(p_known,X))
    a = p_known - r

    # solve
    u = partial_factoring(N, a, X)
    sol = u.solve(2, 1)
    if not sol:
        raise Exception('Cannot factor')
    p, q = sol
    if p * q != N:
        raise Exception('Invalid')
    totient = (p - 1) * (q - 1)

    d = pow(e, -1, totient)
    print(int(pow(c, d, N)).to_bytes(nlen // 8, 'big'))
    return True

def main():
    parser = argparse.ArgumentParser(description='Coppersmith known bits attack')
    parser.add_argument('--N',       type=Integer, nargs='?', help='RSA modulus',                   default=None)
    parser.add_argument('--nlen',    type=Integer, nargs='?', help='RSA modulus bit length',        default=4096)
    parser.add_argument('--c',       type=Integer, nargs='?', help='RSA ciphertext',                default=None)
    parser.add_argument('--e',       type=Integer, nargs='?', help='RSA exponent',                  default=65537)
    parser.add_argument('--rlen',    type=Integer, nargs='?', help='unknown bit length of prime p', default=256)
    parser.add_argument('--p_known', type=Integer, nargs='?', help='known bits of prime p',         default=None)
    parser.add_argument('--test',    action=argparse.BooleanOptionalAction, help='Force modulus generation')
    args = parser.parse_args()
    if not args.test and not args.N:
        parser.print_help()
        return
    run(**vars(args))

if __name__ == '__main__':
    main()

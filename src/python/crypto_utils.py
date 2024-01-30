# cryptography utilities
from Crypto.Util import number
import os


def generate_n_p_q(n_bits):
    p = q = n = None  # constant time allocation
    n_len = 0
    while n_len != n_bits:
        # sample p,q until n is the right size
        p, q = get_prime_over(n_bits // 2), get_prime_over(n_bits // 2)
        assert(p != q)
        n = p*q
        n_len = n.bit_length()
        # print(n, p, q, n_len)
    return n, p, q


def get_prime_over(n_bits):
    """return a random N_BITS prime number, using pycrypto"""
    assert(n_bits < 4000)
    return number.getPrime(n_bits, os.urandom)


def invert(a, modulus):
    """return a inverse % modulus"""
    r, s, _ = eea(a, modulus)
    if r != 1:
        raise ZeroDivisionError('no inverse exists')
    return s % modulus


def eea(a, b):
    """Extended Euclidean Algorigthm, computes a^{-1} modulo b
        See <https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm>"""
    r0, r1 = a, b
    s0, s1 = 1, 0
    t0, t1 = 0, 1
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q*r1
        s0, s1 = s1, s0 - q*s1
        t0, t1 = t1, t0 - q*t1
    return r0, s0, t0

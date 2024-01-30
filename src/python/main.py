# Make use of this library as reference:
# https://github.com/data61/python-paillier
# But don't worry about the features:
# - cli
# - float encryption (assume ints less than some number)
# - a bunch of convenience methods
# - tests (lol, who needs em), just write a driver, that's safe

# we want 3 algorithms for encryption:
# - setup() -> (public_info, secret_info)
# - encrypt_{generator, modulus}(pubkey, plaintext) -> ciphertext
# - decrypt_{generator, modulus}(secretkey, ciphertext) -> plaintext
# and an addition operation over ciphertexts.

# default RSA key bit length, gives more than 128 bits of security.
import random
from crypto_utils import generate_n_p_q, invert
DEFAULT_KEYSIZE = 3072


def main():
    public_key, private_key = generate_keypair()
    plaintext = Plaintext(2357)
    # print(plaintext) # seems fine
    ciphertext = public_key.encrypt(plaintext)
    # print(ciphertext) # seems fine
    decrypted = private_key.decrypt(ciphertext)
    print(decrypted)  # seems not fine

    if decrypted == plaintext:
        print("SUCCESS: normal decrypt")
    else:
        print("FAIL: normal decrypt")

    doubled_ciphertext = ciphertext + ciphertext
    doubled_message = private_key.decrypt(doubled_ciphertext)
    print("doubled_message: ", doubled_message)

    if doubled_message.message == 2357*2:
        print("SUCCESS: additive")
    else:
        print("FAIL: additive")


def generate_keypair(n_bits=DEFAULT_KEYSIZE):
    """Generate a pair of classes: PublicKey and PrivateKey"""
    n, p, q = generate_n_p_q(n_bits)
    public_key = PublicKey(n)
    private_key = PrivateKey(public_key, p, q)
    return public_key, private_key


class PublicKey():
    """A public key and associated encryption methods"""

    def __init__(self, n):
        self.g = n+1  # the convenient generator
        self.n = n
        self.n_square = n*n  # efficiency purposes
        self.max_int = n // 3 - 1

    def __repr__(self):
        public_key_hash = hex(hash(self))  # [2:]
        return "<PublicKey {}>".format(public_key_hash[:12])

    def encrypt(self, plaintext):
        """encrypt plaintext, output ciphertext.
        concisely: c = g**e * r**n mod n**2
        less concisely:
        ciphertext = nude_ciphertext * obfuscator mod n**2
        """
        assert(isinstance(plaintext, Plaintext))
        assert(plaintext.message < self.max_int // 3)

        nude_ciphertext = pow(self.g, plaintext.message, self.n_square)
        r = self.get_random_lt_n()
        obfuscator = pow(r, self.n, self.n_square)

        return Ciphertext(nude_ciphertext * obfuscator % self.n_square, self)

    def get_random_lt_n(self):
        """Return a random number less than n"""
        # systemRandom is os independent
        return random.SystemRandom().randrange(2, self.n)


class PrivateKey():
    """A private key and associated decryption methods"""

    def __init__(self, public_key, p, q):
        if not p*q == public_key.n:
            raise ValueError(
                'given public key does not match the given p and q.')
        if p == q:
            # check that p and q are different,
            # otherwise we can't compute p^-1 mod q
            raise ValueError('p and q have to be different')
        self.public_key = public_key
        # wlog, let p < q
        self.p = min(p, q)
        self.q = max(p, q)

        # Pallier method to compute efficient inverses, page 12
        self.psquare = self.p * self.p
        self.qsquare = self.q * self.q
        self.n = self.p*self.q
        self.nsquare = self.psquare * self.qsquare
        self.lambdaa = (self.p-1) * (self.q-1)
        self.mlambda_inv = invert(self.lambdaa, self.nsquare)
        assert(self.lambdaa * self.mlambda_inv % self.nsquare == 1)

        # self.p_inverse = invert(self.p, self.q)
        # self.hp = self.h_function(self.p, self.psquare)
        # self.hq = self.h_function(self.q, self.qsquare)

    # def h_function(self, x, xsquare):
    #     l_output = self.l_function(pow(self.public_key.g, x - 1, xsquare), x)
    #     return invert(l_output, x)

    def l_function(self, x, n):
        assert((x - 1) // n * n == x-1)
        return (x - 1) // n

    def __repr__(self):
        """don't print the private info, hehe"""
        pub_repr = repr(self.public_key)
        return "<PrivateKey for public key: {}>".format(pub_repr)

    def decrypt(self, ciphertext):
        if not isinstance(ciphertext, Ciphertext):
            raise TypeError('Expected ciphertext to be an Ciphertext'
                            ' not: %s' % type(ciphertext))
        if self.public_key != ciphertext.public_key:
            raise ValueError('ciphertext was encrypted against a '
                             'different key!')

        # construct plaintext
        m_times_lambda = self.l_function(
            pow(ciphertext.ciphertext, self.lambdaa, self.nsquare), self.n)
        message = m_times_lambda * self.mlambda_inv % self.n

        return Plaintext(message)

    # def decrypt2(self, ciphertext):
    #     if not isinstance(ciphertext, Ciphertext):
    #         raise TypeError('Expected ciphertext to be an Ciphertext'
    #                         ' not: %s' % type(ciphertext))
    #     if self.public_key != ciphertext.public_key:
    #         raise ValueError('ciphertext was encrypted against a '
    #                          'different key!')

    #     # construct plaintext
    #     qq = pow(ciphertext.ciphertext, self.q-1, self.qsquare)
    #     decrypt_to_q = self.l_function(qq, self.q) * self.hq % self.q
    #     pp = pow(ciphertext.ciphertext, self.p-1, self.psquare)
    #     decrypt_to_p = self.l_function(pp, self.p) * self.hp % self.p

    #     message = self.crt(decrypt_to_p, decrypt_to_q)
    #     return Plaintext(message)

    # def crt(self, mp, mq):
    #     """Chinese Remainder Theorem. Used in decryption.
    #     Returns m % pq, given
    #     mp = m % p
    #     mq = m % q"""

    #     u = mq - mp * self.p_inverse % self.q
    #     return mp + (u * self.p)


class Plaintext():
    """Some integer message, pass input validation over it"""

    def __init__(self, message):
        if not isinstance(message, int):
            raise TypeError('Expected message type int\nGot message type %s'
                            % type(message))
        self.message = message

    def __repr__(self):
        return "<Plaintext: {}>".format(self.message)

    def __eq__(self, other):
        return self.message == other.message


class Ciphertext():
    """The Pallier encryption of some plaintext"""

    def __init__(self, ciphertext, public_key):
        self.ciphertext = ciphertext
        self.public_key = public_key

    def __repr__(self):
        pub_repr = repr(self.ciphertext)
        return "<Ciphertext {}>".format(pub_repr)

    def __add__(self, other):
        assert(self.public_key == other.public_key)
        return Ciphertext(self.ciphertext * other.ciphertext, self.public_key)


if __name__ == "__main__":
    main()

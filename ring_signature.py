#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
    https://en.wikipedia.org/wiki/Ring_signature

    made adjustements for python 3.6 and PEP 8
    added keccak (sha3_256) option
    bumped moduls to 2048 (from 1024)

    requirements: pycryptodome although pycrypto should work
'''
from __future__ import print_function
import os
import random
from hashlib import sha1, sha3_256
from functools import reduce
from Crypto.PublicKey import RSA


class Ring:
    '''
        from https://en.wikipedia.org/wiki/Ring_signature
    '''
    def __init__(self, k, L=2048, sha_alg='sha3_256'):
        self.k = k
        self.l = L
        print('k: ', k, ' L:', L)
        self.sha_alg = sha_alg

        self.n = len(k)
        self.q = 1 << (L - 1)

    def sign(self, m, z):
        self.permut(m)
        s = [None] * self.n
        u = random.randint(0, self.q)
        c = v = self.E(u)
        for i in (list(range(z + 1, self.n)) + list(range(z))):
            s[i] = random.randint(0, self.q)
            e = self.g(s[i], self.k[i].e, self.k[i].n)
            v = self.E(v ^ e)
            if (i + 1) % self.n == 0:
                c = v
        s[z] = self.g(v ^ u, self.k[z].d, self.k[z].n)
        return [c] + s

    def verify(self, m, X):
        self.permut(m)

        def _f(i):
            return self.g(X[i + 1], self.k[i].e, self.k[i].n)

        def _g(x, i):
            return self.E(x ^ y[i])

        y = list(map(_f, range(len(X) - 1)))
        r = reduce(_g, range(self.n), X[0])
        return r == X[0]

    def permut(self, m):
        if self.sha_alg=='sha1':
            self.p = int(sha1(bytes('%s' % m,'utf8')).hexdigest(),16)
        elif self.sha_alg=='sha3_256':
            self.p = int(sha3_256(bytes('%s' % m,'utf8')).hexdigest(),16)

    def E(self, x):
        msg = '%s%s' % (x, self.p)
        if self.sha_alg=='sha1':
            return int(sha1(bytes(msg,'utf8')).hexdigest(), 16)
        elif self.sha_alg=='sha3_256':
            return int(sha3_256(bytes(msg,'utf8')).hexdigest(), 16)

    def g(self, x, e, n):
        q, r = divmod(x, n)
        if ((q + 1) * n) <= ((1 << self.l) - 1):
            rslt = q * n + pow(r, e, n)
        else:
            rslt = x
        return rslt


def test(detail=True):
    '''
    '''
    def _rn(_):
        return RSA.generate(2048, os.urandom)

    size = 4
    msg1, msg2 = 'hello', 'world!'

    for alg in ['sha1','sha3_256']:
        key = list(map(_rn, range(size)))
        r = Ring(k=key,sha_alg=alg)
        for i in range(size):
            s1 = r.sign(msg1, i)
            s2 = r.sign(msg2, i)
            if detail:
                print(alg,' size: {} : '.format(i),r.verify(msg1, s1) and r.verify(msg2, s2) and not r.verify(msg1, s2))
            assert r.verify(msg1, s1) and r.verify(msg2, s2) and not r.verify(msg1, s2)


if __name__=='__main__':
    '''
    '''
    test()

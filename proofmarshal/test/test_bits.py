# Copyright (C) 2015 Peter Todd <pete@petertodd.org>
#
# This file is part of python-smartcolors.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-smartcolors, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import unittest

from proofmarshal.bits import Bits
from proofmarshal.test import load_test_vectors, x, b2x

class Test_Bits(unittest.TestCase):
    def test_len(self):
        """len(Bits)"""
        def T(expected_length, b):
            self.assertEqual(expected_length, len(b))

        T(0, Bits())
        T(1, Bits([0]))
        T(2, Bits([0,0]))
        T(8, Bits([0]*8))
        T(16, Bits([0]*16))
        T(17, Bits([0]*17))

    def test_iter(self):
        """iter(Bits)"""
        def T(expected_tuple, b):
            self.assertEqual(expected_tuple, tuple(b))
        T((),
          Bits())
        T((0,),
          Bits([0]))
        T((1,),
          Bits([1]))
        T((0,0),
          Bits([0,0]))
        T((1,1),
          Bits([1,1]))
        T((1,0),
          Bits([1,0]))
        T((0,1,1,0,1,0,0,1),
          Bits([0,1,1,0,1,0,0,1]))
        T((0,1,1,0,1,0,0,1,1),
          Bits([0,1,1,0,1,0,0,1,1]))
        T((0,1,1,0,1,0,0,1,1,0,1,0,1,0,1),
          Bits([0,1,1,0,1,0,0,1,1,0,1,0,1,0,1]))
        T((0,1,1,0,1,0,0,1,1,0,1,0,1,0,1,0),
          Bits([0,1,1,0,1,0,0,1,1,0,1,0,1,0,1,0]))

    def test_immutability(self):
        """Bits are immutable"""
        with self.assertRaises(TypeError):
            Bits([0])[0] = 1
        with self.assertRaises(TypeError):
            Bits()[0] = 1

    def test___getitem___with_int(self):
        """__getitem__() special method with ints"""
        self.assertEqual(Bits([0])[0], 0)
        self.assertEqual(Bits([1])[0], 1)

        self.assertEqual(Bits([0])[-1], 0)
        self.assertEqual(Bits([1])[-1], 1)

        self.assertEqual(Bits([0,1])[-2], 0)
        self.assertEqual(Bits([1,0])[-2], 1)

        self.assertEqual(Bits([1,1,1,1,1,1,1,0])[7], 0)
        self.assertEqual(Bits([1,1,1,1,1,1,1,0])[-1], 0)
        self.assertEqual(Bits([1,1,1,1,1,1,1,1,0])[8], 0)
        self.assertEqual(Bits([1,1,1,1,1,1,1,1,0])[-1], 0)

        self.assertEqual(Bits([1]*255 + [0])[255], 0)
        self.assertEqual(Bits([1]*255 + [0])[-1], 0)

        self.assertEqual(Bits([0] + [1]*255)[0], 0)
        self.assertEqual(Bits([0] + [1]*255)[-256], 0)

        with self.assertRaises(IndexError):
            Bits()[0]
        with self.assertRaises(IndexError):
            Bits()[-1]
        with self.assertRaises(IndexError):
            Bits()[1]
        with self.assertRaises(IndexError):
            Bits()[-2]
        with self.assertRaises(IndexError):
            Bits()[8]
        with self.assertRaises(IndexError):
            Bits()[-8]

        with self.assertRaises(IndexError):
            Bits([0])[1]
        with self.assertRaises(IndexError):
            Bits([0])[-2]

        with self.assertRaises(IndexError):
            Bits([0]*8)[8]
        with self.assertRaises(IndexError):
            Bits([0]*8)[-9]

        with self.assertRaises(IndexError):
            Bits([0]*256)[256]
        with self.assertRaises(IndexError):
            Bits([0]*256)[-257]

        with self.assertRaises(TypeError):
            Bits([0])[0.0]
        with self.assertRaises(TypeError):
            Bits([0])['0']
        with self.assertRaises(TypeError):
            Bits([0])[()]
        with self.assertRaises(TypeError):
            Bits([0])[(0,)]

        # subclasses are allowed
        class int_subclass(int):
            pass
        self.assertEqual(Bits([0])[int_subclass(0)], 0)
        with self.assertRaises(IndexError):
            Bits([])[int_subclass(0)]

    def test___getitem___with_slice(self):
        """__getitem__() special method with slices"""
        self.assertEqual(list(Bits([]))[:], [])
        self.assertEqual(list(Bits([]))[0:1], [])
        self.assertEqual(list(Bits([]))[-200:20], [])
        self.assertEqual(list(Bits([]))[-200:20:5], [])

        self.assertEqual(list(Bits([0]))[:], [0])
        self.assertEqual(list(Bits([0]))[0:], [0])
        self.assertEqual(list(Bits([0]))[0:-1], [])
        self.assertEqual(list(Bits([0]))[0:0], [])
        self.assertEqual(list(Bits([0]))[0:1], [0])
        self.assertEqual(list(Bits([0]))[0:2], [0])
        self.assertEqual(list(Bits([0]))[-2:2], [0])

        self.assertEqual(list(Bits([0,1,0,1,1,0,1,0]))[0:4], [0,1,0,1])
        self.assertEqual(list(Bits([0,1,0,1,1,0,1,0]))[2:5], [0,1,1])
        self.assertEqual(list(Bits([0,1,0,1,1,0,1,0]))[-6:-3], [0,1,1])
        self.assertEqual(list(Bits([0,1,0,1,1,0,1,0]))[-6:-1], [0,1,1,0,1])
        self.assertEqual(list(Bits([0,1,0,1,1,0,1,0]))[-6:], [0,1,1,0,1,0])

        self.assertEqual(list(Bits([0]*16 + [1]*16))[15:16], [0])
        self.assertEqual(list(Bits([0]*16 + [1]*16))[15:17], [0,1])
        self.assertEqual(list(Bits([0]*16 + [1]*16))[14:18], [0,0,1,1])

        self.assertEqual(list(Bits([0]*16 + [1]*16))[8:24], [0]*8 + [1]*8)
        self.assertEqual(list(Bits([0]*16 + [1]*16))[8:25], [0]*8 + [1]*9)

        # Don't create new objects unnecessarily
        b = Bits()
        self.assertIs(b, b[:])
        self.assertIs(b, b[0:])
        self.assertIs(b, b[:-1])
        self.assertIs(b, b[0:-1])

        b = Bits([1,1,0,1,0,1,1,0])
        self.assertIs(b, b[0:])
        self.assertIs(b, b[0:200])
        self.assertIs(b, b[-8:])

        with self.assertRaises(TypeError):
            Bits()['b':'a']
        with self.assertRaises(TypeError):
            Bits()[0.0:]

    def test___hash__(self):
        """__hash__() special method"""

    def test_equality(self):
        """Equality comparisons"""
        def T(a,b):
            self.assertTrue(a == b)
            self.assertTrue(b == a)
            self.assertFalse(a != b)
            self.assertFalse(b != a)

        def F(a,b):
            self.assertTrue(a != b)
            self.assertTrue(b != a)
            self.assertFalse(a == b)
            self.assertFalse(b == a)

        T(Bits([]), Bits([]))
        T(Bits([0]), Bits([0]))
        T(Bits([1]), Bits([1]))
        T(Bits([0,1]), Bits([0,1]))
        T(Bits([0]*8), Bits([0]*8))
        T(Bits([0,1,1,0,1,0,0,1]), Bits([0,1,1,0,1,0,0,1]))
        T(Bits([0,1,1,0,1,0,0,1]*2), Bits([0,1,1,0,1,0,0,1]*2))
        T(Bits([0,1,1,0,1,0,0,1]*2+[0]), Bits([0,1,1,0,1,0,0,1]*2+[0]))

        F(Bits([0]), Bits([]))
        F(Bits([0]), Bits([1]))
        F(Bits([1,1]), Bits([0,0]))
        F(Bits([0,1]), Bits([1,0]))
        F(Bits([0,1,1,0,1,0,0,1]), Bits([0,1,1,0,1,0,0,0]))
        F(Bits([0,1,1,0,1,0,0,1]), Bits([0,1,1,0,1,0,0,1,0]))
        F(Bits([0,1,1,0,1,0,0,1]*2), Bits([0,1,1,0,1,0,0,1]*2+[0]))
        F(Bits([0,1,1,0,1,0,0,1]*2+[1]), Bits([0,1,1,0,1,0,0,1]*2+[0]))

    def test_op_add(self):
        """Operator +"""
        def T(a,b):
            a = Bits(a)
            b = Bits(b)
            self.assertEqual(a+b, Bits(a + b))

        T([],[])
        T([0],[])
        T([0],[1])

        # brute-force test all possible left and rights over zero to three
        # bytes of range for left and right
        for n in range(23):
            for m in range(23):
                # left ends in a 1, right ends in a zero and is all ones, to
                # distinguish them
                left = [0]*n + [1]
                right = [0] + [1]*m
                actual = Bits(left) + Bits(right)
                expected = Bits(left + right)
                self.assertEqual(actual, expected)

        # Don't create new objects unnecessarily
        b = Bits([0])
        self.assertIs(b + Bits(), b)
        self.assertIs(Bits() + b, b)

    def test_op_invert(self):
        """Operator ~"""

        # Inversion of nothing is nothing
        self.assertIs(~Bits(), Bits())

        a = [1,0,1,0,1,0,1,0, 0,1,0,1,0,1,0,1, 1,1,0,0,1,1,0,0]
        b = [0,1,0,1,0,1,0,1, 1,0,1,0,1,0,1,0, 0,0,1,1,0,0,1,1]

        for l in range(len(a)+1):
            self.assertEqual(~Bits(a[:l]), Bits(b[:l]))

    def test_startswith(self):
        """startswith() method"""
        def T(lhs, rhs):
            lhs = Bits(lhs)
            rhs = Bits(rhs)
            self.assertTrue(lhs.startswith(rhs))
        def F(lhs, rhs):
            lhs = Bits(lhs)
            rhs = Bits(rhs)
            self.assertFalse(lhs.startswith(rhs))

        # Everything starts with nothing
        T([], [])
        T([0], [])
        T([0]*8, [])
        T([0]*9, [])

        # While nothing doesn't start with anything (other than nothing)
        F([], [0])
        F([], [0]*2)
        F([], [0]*8)
        F([], [0]*9)
        F([], [1])
        F([], [1]*2)
        F([], [1]*8)
        F([], [1]*9)

        # brute-force test combinations
        for n in range(23):
            for m in range(23-n):
                lhs = Bits([0]*n + [1] + [0]*m)

                # lhs should start with all subsets of itself
                for l in range(len(lhs)+1):
                    lhs_prefix = lhs[0:l]
                    self.assertTrue(lhs.startswith(lhs_prefix))

                # lhs does not start with itself plus a bit
                self.assertFalse(lhs.startswith(lhs + Bits([0])))

                # or any prefix of itself with the first or last bit changed
                for l in range(1,len(lhs)):
                    inverted_msb = Bits([not lhs[0]]) + lhs[1:l]
                    self.assertFalse(lhs.startswith(inverted_msb))

                    inverted_lsb = lhs[:l-1] + Bits([not lhs[l-1]])
                    self.assertFalse(lhs.startswith(inverted_lsb))

        with self.assertRaises(TypeError):
            Bits().startswith(None)
        with self.assertRaises(TypeError):
            Bits().startswith([])

    def test_common_prefix(self):
        """common_prefix() method"""
        self.assertTrue(Bits([0]).common_prefix(Bits([1])) == Bits([]))

        with self.assertRaises(TypeError):
            Bits().common_prefix(None)
        with self.assertRaises(TypeError):
            Bits().common_prefix([])


        # Don't create objects unnecessarily
        b = Bits()
        self.assertIs(b.common_prefix(b), b)
        self.assertIs(b.common_prefix(Bits([0])), b)

        # Brute force. Common prefix of 0-24 0's, with a and b having that
        # prefix and 0-16 0's and 1's respectively
        master_common_prefix = Bits([0]*24)
        for l in range(25):
            common_prefix = master_common_prefix[:l]

            for n in range(17):
                a = common_prefix + Bits([0]*n)

                for m in range(17):
                    b = common_prefix + Bits([1] + [0]*(m-1))

                    self.assertEqual(a.common_prefix(b), common_prefix)
                    self.assertEqual(b.common_prefix(a), common_prefix)

                    # try same but on negated bits
                    not_common_prefix = ~common_prefix
                    not_a = ~a
                    not_b = ~b
                    self.assertEqual(not_a.common_prefix(not_b), not_common_prefix)
                    self.assertEqual(not_b.common_prefix(not_a), not_common_prefix)

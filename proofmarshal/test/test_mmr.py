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

from proofmarshal.mmr import MerkleMountainRange, make_mmr_subclass
from proofmarshal.serialize import UInt64, HashTag

@make_mmr_subclass
class IntMMR(MerkleMountainRange):
    __slots__ = []
    HASHTAG = HashTag('738b5a85-d6f1-4873-9c21-300a01166f1d')
    VALUE_SERIALIZER = UInt64


class Test_MerkleMountainRange(unittest.TestCase):
    def test_empty_mmr(self):
        """Properties of an empty MerkleMountainRange"""

        # Empty nodes are singletons
        self.assertIs(IntMMR(), IntMMR())

        m0 = IntMMR()

        self.assertIs(m0.__class__, m0.EmptyNodeClass)
        self.assertEqual(len(m0), 0)

        # Indexing should always fail
        with self.assertRaises(IndexError):
            m0[0]
        with self.assertRaises(IndexError):
            m0[1]
        with self.assertRaises(IndexError):
            m0[-1]

        # But the wrong type raises a TypeError, not a IndexError
        with self.assertRaises(TypeError):
            m0['0']

        # Slices however return self as a slice of nothing is always nothing
        self.assertIs(m0[:], m0)
        self.assertIs(m0[:], m0)
        self.assertIs(m0[0:1000], m0)
        self.assertIs(m0[100:1000], m0)

        with self.assertRaises(TypeError):
            m0['0':]
        with self.assertRaises(TypeError):
            m0[:'0']
        with self.assertRaises(TypeError):
            m0[::'0']

        # Iterating, reverse or not, gives you nothing
        self.assertEqual([], list(iter(m0)))
        self.assertEqual([], list(reversed(m0)))

    def test_leaf_mmr(self):
        """Properties of a MerkleMountainRange with a single item"""

        # Appending to the empty MMR gives us a leaf node
        m1 = IntMMR().append(0)
        self.assertIs(m1.__class__, IntMMR.LeafNodeClass)

        self.assertEqual(len(m1), 1)

        # Simple indexing
        self.assertEqual(m1[0], 0)
        self.assertEqual(m1[-1], 0)
        with self.assertRaises(IndexError):
            m1[1]
        with self.assertRaises(IndexError):
            m1[-2]
        with self.assertRaises(TypeError):
            m1['a']

        # Slices, note how objects are reused where appropriate
        self.assertIs(m1[:], m1)
        self.assertIs(m1[1:], IntMMR.EmptyNodeClass())

        with self.assertRaises(TypeError):
            m1['0':]
        with self.assertRaises(TypeError):
            m1[:'0']
        with self.assertRaises(TypeError):
            m1[::'0']

        # Iteration
        self.assertEqual(list(iter(m1)), [0])
        self.assertEqual(list(reversed(m1)), [0])

    def test_immutable(self):
        """MMR's are immutable"""
        m = IntMMR()

        for i in range(8):
            with self.assertRaises(TypeError):
                del m[0]
            with self.assertRaises(TypeError):
                m[0] = 1

            m = m.append(i)

    def test_is_perfect_tree(self):
        """MerkleMountainRange.is_perfect_tree()"""
        def T(n):
            m = IntMMR([0]*n)
            self.assertTrue(m.is_perfect_tree())
        def F(n):
            m = IntMMR([0]*n)
            self.assertFalse(m.is_perfect_tree())

        F(0)
        T(1)
        T(2)
        F(3)
        T(4)
        F(5)
        F(6)
        F(7)
        T(8)
        F(9)

    def test_len(self):
        """len()"""
        m = IntMMR()
        for expected_length in range(32+1):
            self.assertEqual(expected_length, len(m))
            m = m.append(expected_length)

    def test_iter(self):
        """iter(<MerkleMountainRange>) and reversed(<MerkleMountainRange>)"""
        m = IntMMR()
        expected = []
        for i in range(32+1):

            actual = list(iter(m))
            self.assertEqual(expected, actual)

            actual_reversed = list(reversed(m))
            expected_reversed = list(reversed(expected))
            self.assertEqual(expected_reversed, actual_reversed)

            m = m.append(i)
            expected.append(i)

    def test___getitem___with_ints(self):
        """__getitem__() with integer indexes"""
        m = IntMMR()
        for i in range(32+1):
            m = m.append(i)

            for j in range(i+1):
                self.assertEqual(m[j], j)

    def test___getitem___with_slices(self):
        """__getitem__() with slices"""
        # FIXME: not supported yet

        # check that perfect trees are returned unchanged

    def test_serialize(self):
        self.assertEqual(IntMMR().serialize(),
                         bytes.fromhex('00' '00'))
        self.assertEqual(IntMMR([0x0f]).serialize(),
                         bytes.fromhex('00' '010f'))
        self.assertEqual(IntMMR([0x0e, 0x0f]).serialize(),
                         bytes.fromhex('00' '02' '00010e' '00010f' '02'))

    def test_deserialize(self):
        self.assertEqual(IntMMR(),
                         IntMMR.deserialize(bytes.fromhex('00' '00')))
        self.assertEqual(IntMMR([0x0f]),
                         IntMMR.deserialize(bytes.fromhex('00' '010f')))
        self.assertEqual(IntMMR([0x0e, 0x0f]),
                         IntMMR.deserialize(bytes.fromhex('00' '02' '00010e' '00010f' '02')))

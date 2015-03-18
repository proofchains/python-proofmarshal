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

import itertools
import unittest

from proofmarshal.merbinnertree import MerbinnerTree, make_MerbinnerTree_subclass
from proofmarshal.serialize import UInt64, Digest, HashTag
from proofmarshal.bits import Bits

def str_tree(tip):
    if tip.__class__ is IntMBTree.EmptyNodeClass:
        return '()'

    elif tip.__class__ is IntMBTree.LeafNodeClass:
        return '%s' % bin(tip.value)

    else:
        return '%s:(%s,%s)' % (''.join(['1' if b else '0' for b in tip.prefix]),
                               str_tree(tip.left), str_tree(tip.right))


@make_MerbinnerTree_subclass
class IntMBTree(MerbinnerTree):
    __slots__ = []

    HASHTAG = HashTag('2bb60984-0486-41ab-aad6-bd5b1586bd14')

    KEY_SERIALIZER = Digest
    VALUE_SERIALIZER = UInt64

    @staticmethod
    def key2prefix(key):
        return Bits.from_bytes(key)

class Test_MerbinnerTree(unittest.TestCase):
    def test_empty_node(self):
        """Properties of an empty MerbinnerTree"""

        # Empty nodes are singletons
        self.assertIs(IntMBTree(), IntMBTree())

        m0 = IntMBTree()

        self.assertIs(m0.__class__, m0.EmptyNodeClass)
        self.assertEqual(len(m0), 0)

        # Prefix is zero length
        self.assertEqual(len(m0.prefix), 0)

        # Indexing should always fail
        with self.assertRaises(KeyError):
            m0[b'\x00'*32]
        with self.assertRaises(KeyError):
            m0[b'\xff'*32]

        # But the wrong type raises a TypeError, not a KeyError
        with self.assertRaises(TypeError):
            m0['0'*32]

        # FIXME: slices?

        # Iterating gives you nothing
        self.assertEqual([], list(iter(m0.items())))

    def test_leaf_node(self):
        """Properties of a MerbinnerTree with a single item"""
        # Empty nodes are singletons
        m0 = IntMBTree()
        m1 = m0.put(b'\x00'*32, 0)

        self.assertIs(m1.__class__, m0.LeafNodeClass)
        self.assertEqual(len(m0), 0)

        # Prefix is 256 bits - length of key in bits
        self.assertEqual(len(m1.prefix), 256)

        # Indexing FIXME

        # Wrong type raises a TypeError, not a KeyError
        with self.assertRaises(TypeError):
            m0['0'*32]

        # FIXME: slices?

        # Iterating FIXME

    def test_put(self):
        """MerbinnerTree.put()"""
        m0 = IntMBTree()

        # Empty is turned into a leaf
        m1 = m0.put(b'\x00'*32, 0x00)
        self.assertIs(m1.__class__, IntMBTree.LeafNodeClass)
        self.assertEqual(m1.key, b'\x00'*32)
        self.assertEqual(m1.value, 0)

        # Leaf is turned into an inner
        m2 = m1.put(b'\x0f'*32, 0x0f)
        self.assertIs(m2.__class__, IntMBTree.InnerNodeClass)
        self.assertEqual(len(m2.prefix), 4)
        self.assertEqual(m2.right.key, b'\x0f'*32)
        self.assertEqual(m2.right.value, 0x0f)
        # m1 is reused as child of m2
        self.assertIs(m2.left, m1)

        # New tip is less specific than old tip...
        m3 = m2.put(b'\x2f'*32, 0x2f)
        self.assertEqual(len(m3.prefix), 2)
        self.assertEqual(m3.right.key, b'\x2f'*32)
        self.assertEqual(m3.right.value, 0x2f)

        # ...so m2 reused as child of m3
        self.assertIs(m3.left, m2)

        # Changing m3.right this time, which will require the tip to be
        # rewritten rather than reused.
        m4 = m3.put(b'\x3f'*32, 0x3f)
        self.assertEqual(len(m4.prefix), 2)

        # tip.left is unchanged and reused
        self.assertIs(m4.left, m3.left)

        # tip.right changed from leaf to inner, with previous leaf reused
        self.assertIs(m4.right.left, m3.right)
        self.assertEqual(m4.right.right.key, b'\x3f'*32)
        self.assertEqual(m4.right.right.value, 0x3f)

    def test___getitem__(self):
        """MerbinnerTree[key]"""
        expected_missing_keys = [b'\xff'*32]

        expected_items = []
        m = IntMBTree()
        for i in range(32):
            for key, value in expected_items:
                self.assertEqual(m[key], value)

            for key in expected_missing_keys:
                try:
                    m[key]
                except KeyError as exp:
                    self.assertEqual(exp.args[0], key)

            new_key = bytes([i])*32

            m = m.put(new_key, i)
            expected_items.append((new_key, i))
            expected_missing_keys.append(new_key[:-2] + b'\xff\xff')


    def test_remove(self):
        """MerbinnerTree.remove()"""
        m0 = IntMBTree()

        # Can't remove anything from the empty node
        with self.assertRaises(KeyError):
            m0.remove(b'\x00'*32)

        # Removing the only item in the tree results in an empty node
        m1 = m0.put(b'\x00'*32, 0x00)
        self.assertIs(m1.remove(b'\x00'*32), IntMBTree())

        # Removing a non-existant item
        with self.assertRaises(KeyError):
            m0.remove(b'\xff'*32)

        # Removing either key results in promotion of the other leaf to the tip
        m2 = m1.put(b'\x0f'*32, 0x0f)
        self.assertIs(m2.remove(b'\x00'*32), m2.right)
        self.assertIs(m2.remove(b'\x0f'*32), m2.left)

        with self.assertRaises(KeyError):
            m2.remove(b'\xff'*32)

        m3 = m2.put(b'\x2f'*32, 0x2f)

        # Promotion of old inner node tip to new tip
        self.assertIs(m3.remove(b'\x2f'*32), m3.left)

        # And recreation with remaining two items after removing a deeper part
        # of the tree; both cases.
        m3a = m3.remove(b'\x00'*32)
        self.assertIs(m3a.left, m3.left.right)
        self.assertIs(m3a.right, m3.right)
        m3b = m3.remove(b'\x0f'*32)
        self.assertIs(m3b.left, m3.left.left)
        self.assertIs(m3b.right, m3.right)

    def test_immutable(self):
        """MerbinnerTree's are immutable"""
        m = IntMBTree()

        for i in range(8):
            with self.assertRaises(TypeError):
                del m[0]
            with self.assertRaises(TypeError):
                m[0] = 1

            # FIXME

    def test_len(self):
        """len(<MerbinnerTree>)"""
        m = IntMBTree()
        for expected_length in range(256):
            self.assertEqual(len(m), expected_length)
            m = m.put(bytes([expected_length])*32, expected_length)


    def test_iter(self):
        """iter(<MerbinnerTree>) and reversed(<MerbinnerTree>)"""
        pass # FIXME

    def test_issubset(self):
        """MerbinnerTree.issubset()"""

        items = [(bytes([i])*32,i) for i in range(5)]
        items = [i for i in range(5)]

        def all_subsets(n):
            """Yield all possible merbinner tree subsets with up to n items"""
            if n == 0:
                yield IntMBTree()

            else:
                for base_tree in all_subsets(n - 1):
                    yield base_tree
                    yield base_tree.put(bytes([n])*32, n)

        # Brute force issubset() against all possible combinations of subsets,
        # checking against set's implementation each time.
        n = 5
        for a in all_subsets(n):
            for b in all_subsets(n):
                self.assertEqual(a.issubset(b), set(a.values()).issubset(set(b.values())))

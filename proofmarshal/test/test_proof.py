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

from proofmarshal.proof import *
from proofmarshal.serialize import *

class FooProof(Proof):
    HASH_HMAC_KEY = b'\x16\xdcj\x9bS\x9b\xf0\xf3I\xe0\xdaL\xbfF\xc0g'

    __slots__ = ['n']
    SERIALIZED_ATTRS = [('n', UInt8)]

class BarProof(Proof):
    HASH_HMAC_KEY = b'Z\xf8\x0bZ\x7f0\x89\x88#\x16!\x88\xe2\x06\xe2&'

    __slots__ = ['left', 'right', 'nonproof_attr']
    SERIALIZED_ATTRS = [('left',  FooProof),
                        ('right', FooProof),
                        ('nonproof_attr', UInt8)]

    def sum(self):
        return self.left.n + self.right.n

    def descend(self, side):
        if side:
            return self.right
        else:
            return self.left

class Test_Proof(unittest.TestCase):
    def test_pruning(self):
        """Proof pruning"""

        bar = BarProof(left=FooProof(n=1), right=FooProof(n=2), nonproof_attr=3)

        # Totally unpruned, so everything is accessible.
        self.assertEqual(bar.left.n, 1)
        self.assertEqual(bar.right.n, 2)
        self.assertEqual(bar.nonproof_attr, 3)

        # The bar instance is fully immutable

        # Prune bar, giving us a copy of bar with all prunable members replaced
        # by PrunedProof instances.
        pruned_bar = bar.prune()

        self.assertTrue(pruned_bar.is_pruned)
        self.assertTrue(pruned_bar.is_fully_pruned)

        pruned_bar.hash
        pruned_bar.descend(True)
        pruned_bar.descend(True)

        self.assertTrue(pruned_bar.is_pruned)
        self.assertFalse(pruned_bar.is_fully_pruned)

    def test_unpruned_serialization(self):
        """Serialization of unpruned proofs"""
        self.assertEqual(FooProof(n=0xf).serialize(), b'\x00' + b'\x0f')

    def test_unpruned_deserialization(self):
        """Deserialization of unpruned proofs"""
        f = FooProof.deserialize(b'\x00' + b'\x0f')
        self.assertIs(f.__class__, FooProof)
        self.assertIs(f.n, 0xf)

        self.assertFalse(f.is_pruned)
        self.assertFalse(f.is_fully_pruned)

    def test_fully_pruned_serialization(self):
        """Serialization of fully pruned proofs"""
        f = FooProof(n=0xf)
        f_pruned = f.prune()

        self.assertEqual(f_pruned.serialize(),
                         b'\xff' + f_pruned.hash)

    def test_fully_pruned_deserialization(self):
        """Serialization of fully pruned proofs"""
        f = FooProof.deserialize(b'\xff' + b'\x00'*32)

        self.assertTrue(f.is_pruned)
        self.assertTrue(f.is_fully_pruned)
        self.assertEqual(f.hash, b'\x00'*32)

    def test_pruned_serialization(self):
        """Serialization of pruned proofs"""
        f1 = FooProof(n=1)
        f2 = FooProof(n=2)
        b = BarProof(left=f1, right=f2, nonproof_attr=3)

        b = b.prune()

        self.assertTrue(b.is_pruned)
        self.assertTrue(b.is_fully_pruned)

        # Depend on b's non-pruned attribute, which makes b no longer fully
        # pruned.
        self.assertEqual(b.nonproof_attr, 3)

        self.assertEqual(b.serialize(),
                         (b'\x00' + # not pruned
                          b'\xff' + f1.hash + # left fully pruned
                          b'\xff' + f2.hash + # right fully pruned
                          b'\x03')) # non-proof attribute

        # Depend on b.left.hash, which does *not* change the serialization
        self.assertEqual(b.left.hash, f1.hash)
        self.assertEqual(b.serialize(),
                         (b'\x00' + # not pruned
                          b'\xff' + f1.hash + # left fully pruned
                          b'\xff' + f2.hash + # right fully pruned
                          b'\x03')) # non-proof attribute

        # Using b.left.n however does unprune b.left, changing the serialization
        self.assertEqual(b.left.n, 1)
        self.assertEqual(b.serialize(),
                         (b'\x00' + # not pruned
                          b'\x00' + b'\x01' + # left not pruned
                          b'\xff' + f2.hash + # right fully pruned
                          b'\x03')) # non-proof attribute

    def test_pruned_deserialization(self):
        """Deserialization of pruned proofs"""

        b = BarProof.deserialize(b'\x00' + # not pruned
                                 b'\xff' + b'\x11'*32 + # fully pruned left
                                 b'\xff' + b'\x22'*32 + # fully pruned right
                                 b'\x03') # non-proof attribute

        self.assertTrue(b.is_pruned)
        self.assertFalse(b.is_fully_pruned)

        self.assertTrue(b.left.is_fully_pruned)
        self.assertTrue(b.right.is_fully_pruned)
        self.assertEqual(b.nonproof_attr, 3)

        b = BarProof.deserialize(b'\x00' + # not pruned
                                 b'\x00' + b'\x01' + # unpruned left
                                 b'\xff' + b'\x22'*32 + # fully pruned right
                                 b'\x03') # non-proof attribute

        self.assertTrue(b.is_pruned)
        self.assertFalse(b.is_fully_pruned)

        self.assertFalse(b.left.is_fully_pruned)
        self.assertFalse(b.left.is_pruned)
        self.assertEqual(b.left.n, 1)

        self.assertTrue(b.right.is_fully_pruned)

        self.assertEqual(b.nonproof_attr, 3)


class FooUnion(ProofUnion):
    HASH_HMAC_KEY = None

@FooUnion.declare_union_subclass
class EmptyFooUnion(FooUnion):
    HASH_HMAC_KEY = b'\x00'*32
    SERIALIZED_ATTRS = []

@FooUnion.declare_union_subclass
class LeafFooUnion(FooUnion):
    HASH_HMAC_KEY = b'\x11'*32
    SERIALIZED_ATTRS = [('value', UInt8)]

@FooUnion.declare_union_subclass
class InnerFooUnion(FooUnion):
    HASH_HMAC_KEY = b'\x22'*32
    SERIALIZED_ATTRS = [('left', FooUnion),
                        ('right', FooUnion)]

class Test_StructUnion(unittest.TestCase):
    def test_checkinstance(self):
        FooUnion.check_instance(EmptyFooUnion())
        FooUnion.check_instance(LeafFooUnion(value=0))
        FooUnion.check_instance(InnerFooUnion(left=EmptyFooUnion(), right=EmptyFooUnion()))

        with self.assertRaises(SerializerTypeError):
            FooUnion.check_instance(None)

        # The FooUnion class is *not* part of the union, it's just the
        # serializer for classes in it
        with self.assertRaises(SerializerTypeError):
            FooUnion.check_instance(FooUnion)

    def test_serialization(self):
        self.assertEqual(EmptyFooUnion().serialize(), b'\x00\x00')
        self.assertEqual(LeafFooUnion(value=0xf).serialize(), b'\x00\x01\x0f')
        self.assertEqual(InnerFooUnion(left=EmptyFooUnion(),
                                       right=LeafFooUnion(value=0xf)).serialize(),
                         b'\x00\x02\x00\x00\x00\x01\x0f')

    def test_hashing(self):
        def H(cls, hmac_msg):
            return hmac.HMAC(cls.HASH_HMAC_KEY, hmac_msg, hashlib.sha256).digest()

        empty = EmptyFooUnion()
        expected_empty_hash = H(EmptyFooUnion, b'')
        self.assertEqual(empty.hash, expected_empty_hash)

        leaf = LeafFooUnion(value=0x0f)
        expected_leaf_hash = H(LeafFooUnion, b'\x0f')
        self.assertEqual(leaf.hash, expected_leaf_hash)

        inner = InnerFooUnion(left=empty, right=leaf)
        expected_inner_hash = H(InnerFooUnion, expected_empty_hash + expected_leaf_hash)
        self.assertEqual(inner.hash, expected_inner_hash)


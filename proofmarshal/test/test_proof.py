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

import hashlib
import hmac
import unittest

from proofmarshal.proof import *
from proofmarshal.serialize import *

class FooProof(Proof):
    HASHTAG = HashTag('19e5278a-76cc-479c-8713-e7648636979c')

    __slots__ = ['n']
    SERIALIZED_ATTRS = [('n', UInt8)]

class BarProof(Proof):
    HASHTAG = HashTag('4c3cce55-0a90-404e-baf3-a6720205e8ab')

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
    def test_hash(self):
        """Proofs are hashable"""
        f1a = FooProof(n=1)
        f1b = FooProof(n=1)
        f2 = FooProof(n=2)

        self.assertEqual(hash(f1a), hash(f1b))
        self.assertEqual(len(set([f1a, f1b])), 1)

        self.assertNotEqual(hash(f1a), hash(f2))
        self.assertEqual(len(set([f1a, f1b, f2])), 2)

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
                         b'\xff' + f_pruned.data_hash)

    def test_fully_pruned_deserialization(self):
        """Serialization of fully pruned proofs"""
        f = FooProof.deserialize(b'\xff' + b'\x00'*32)

        self.assertTrue(f.is_pruned)
        self.assertTrue(f.is_fully_pruned)
        self.assertEqual(f.data_hash, b'\x00'*32)

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
                          b'\xff' + f1.data_hash + # left fully pruned
                          b'\xff' + f2.data_hash + # right fully pruned
                          b'\x03')) # non-proof attribute

        # Depend on b.left.hash, which does *not* change the serialization
        self.assertEqual(b.left.hash, f1.hash)
        self.assertEqual(b.serialize(),
                         (b'\x00' + # not pruned
                          b'\xff' + f1.data_hash + # left fully pruned
                          b'\xff' + f2.data_hash + # right fully pruned
                          b'\x03')) # non-proof attribute

        # Using b.left.n however does unprune b.left, changing the serialization
        self.assertEqual(b.left.n, 1)
        self.assertEqual(b.serialize(),
                         (b'\x00' + # not pruned
                          b'\x00' + b'\x01' + # left not pruned
                          b'\xff' + f2.data_hash + # right fully pruned
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

    def test_PrunedError(self):
        """PrunedError raised when pruned attribute is not available"""

        orig = BarProof(left=FooProof(n=1), right=FooProof(n=2), nonproof_attr=3)
        pruned = BarProof.deserialize(orig.prune().serialize())

        try:
            pruned.left.n
        except PrunedError as exp:
            self.assertEqual(exp.attr_name, 'left')
            self.assertIs(exp.instance, pruned)


class FooVarProof(VarProof):
    HASHTAG = HashTag('0790a99e-0a12-4677-b4c6-57054039b9cf')

@FooVarProof.declare_variant
class EmptyFooVarProof(FooVarProof):
    SUB_HASHTAG = HashTag('a5516ff0-99a7-4a00-b918-8d30ea6f25b1')
    SERIALIZED_ATTRS = []

@FooVarProof.declare_variant
class LeafFooVarProof(FooVarProof):
    SUB_HASHTAG = HashTag('69cd3faa-b1e7-48e4-be6e-d73f6644829b')
    SERIALIZED_ATTRS = [('value', UInt8)]

@FooVarProof.declare_variant
class InnerFooVarProof(FooVarProof):
    SUB_HASHTAG = HashTag('e540376a-b7b4-4b06-8d25-b7b00cf7e081')
    SERIALIZED_ATTRS = [('left', FooVarProof),
                        ('right', FooVarProof)]

@FooVarProof.declare_variant
class DerivedHmacFooVarProof(FooVarProof):
    SUB_HASHTAG = HashTag('6d0ef952-6621-4a85-8f4c-23ae0427c937')
    SERIALIZED_ATTRS = []

class Test_VarProof(unittest.TestCase):
    def test_checkinstance(self):
        FooVarProof.check_instance(EmptyFooVarProof())
        FooVarProof.check_instance(LeafFooVarProof(value=0))
        FooVarProof.check_instance(InnerFooVarProof(left=EmptyFooVarProof(), right=EmptyFooVarProof()))

        with self.assertRaises(SerializerTypeError):
            FooVarProof.check_instance(None)

        # The FooVarProof class is *not* part of the union, it's just the
        # serializer for classes in it
        with self.assertRaises(SerializerTypeError):
            FooVarProof.check_instance(FooVarProof)

    def test_serialization(self):
        self.assertEqual(EmptyFooVarProof().serialize(), b'\x00\x00')
        self.assertEqual(LeafFooVarProof(value=0xf).serialize(), b'\x00\x01\x0f')
        self.assertEqual(InnerFooVarProof(left=EmptyFooVarProof(),
                                       right=LeafFooVarProof(value=0xf)).serialize(),
                         b'\x00\x02\x00\x00\x00\x01\x0f')

    def test_deserialization(self):
        x = EmptyFooVarProof()
        self.assertEqual(EmptyFooVarProof.deserialize(x.serialize()), x)

        x = LeafFooVarProof(value=0xf)
        self.assertEqual(LeafFooVarProof.deserialize(x.serialize()), x)

        x = InnerFooVarProof(left=EmptyFooVarProof(), right=LeafFooVarProof(value=0xf))
        self.assertEqual(InnerFooVarProof.deserialize(x.serialize()), x)

    def test_hashing(self):
        def H(cls, msg):
            data_hash = hashlib.sha256(msg).digest()
            return hashlib.sha256(cls.HASHTAG + data_hash).digest()

        empty = EmptyFooVarProof()
        expected_empty_hash = H(EmptyFooVarProof, b'')
        self.assertEqual(empty.hash, expected_empty_hash)

        leaf = LeafFooVarProof(value=0x0f)
        expected_leaf_hash = H(LeafFooVarProof, b'\x0f')
        self.assertEqual(leaf.hash, expected_leaf_hash)

        inner = InnerFooVarProof(left=empty, right=leaf)
        expected_inner_hash = H(InnerFooVarProof, expected_empty_hash + expected_leaf_hash)
        self.assertEqual(inner.hash, expected_inner_hash)

    def test_hmac_derivation(self):
        self.assertNotEqual(FooVarProof.HASHTAG, DerivedHmacFooVarProof.HASHTAG)
        self.assertEqual(DerivedHmacFooVarProof.HASHTAG,
                         HashTag('498430c5-4ed1-8dd5-3f09-97e0725c3407'))

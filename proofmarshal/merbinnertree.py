# Copyright (C) 2014-2015 Peter Todd <pete@petertodd.org>
#
# This file is part of python-proofmarshal.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-proofmarshal, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import hashlib
import hmac
import operator

import proofmarshal.proof

from proofmarshal.bits import Bits, BitsSerializer

"""(Summed) Merkleized Binary Radix Tree support

Motivation
==========

We have a (potentially empty) key:value mapping D = {k_0:v_0 ... k_n:v_n}. The
map may contain duplicate values, but not duplicate keys. We wish to hash that
map into a single commitment MBTree(M) and with that commitment prove the
following efficiently in both time and space:

1) Non-existence of a key. Given MBTree(D) and k prove k ∉ D

2) Value associated with a key. Given MBTree(D) and k s.t. k ∈ D prove D[k] = v

3) Modification of values. Given MBTree(D) and k:v prove that changing v to v'
   results in MBTree(D')

It must not be possible to create pairs of contradictory proofs even for fake
commitments, however it is permissible for there to exist "valid" proofs for
fake commitments.

Concretely suppose we have a fake commitment M such that there exists no D for
which MBTree(D) = M. It is permissible if there exists a proof P for which the
proof verification function returns true for the statement D[k] = v, where D is
the list M claims to commit too. However there must not exist a contradictory
proof P' for which the proof verification function returns true for the
statement M[k] = v', where v != v'


Simplified formal construction
==============================

The hash of an empty map is:

    MBTree({}) = H(0)

The hash of a map with one entry (also known as a leaf hash) is:

    MBTree({k_0:v_0}) = H(1 || H(k_0) || H(v_0))

For n > 1, p be the longest prefix such that all k ∈ D start with p. Let D_l be
the subset of D such that all k_l ∈ D_l start with p + 0, and let D_r be the
subset of D such that all k_r ∈ D_r start with p || 1. The MBTree() of an
n-element list D is then defined recursively as:

    MBTree(D) = H(2 || p || MBTree(D_l) || MBTree(D_r))


Design
======

FIXME: needs more formal fleshing out

The "big idea" behind a merbinner tree is that every node in the tree has a
n-bit binary prefix, where 0 <= n, such that any child of the node starts with
that prefix. Equally, as leaf nodes have a prefix equal to the (hash of) the
key, any key under the node will also start with that prefix. Inner nodes
always have the longest possible prefix. This simple invariant means that all
logic is context free, depending only on the action being performed and the
node itself. Including the full prefix in every hash maintains domain
separation and immutability, as the hash of any inner node remains valid and
unique for the items under it.

"""


class MerbinnerTree(proofmarshal.proof.ProofUnion):
    """Merbinner tree"""
    __slots__ = []

    TAG = None

    SUM_IDENTITY = 0

    KEY_SERIALIZER = None
    VALUE_SERIALIZER = None

    @staticmethod
    def key2prefix(key):
        return key.hash

    def __new__(cls, iterable=()):
        """Create a new merbinner tree"""

        if hasattr(iterable, 'items'):
            iterable = iterable.items()

        self = cls.EmptyNodeClass()
        for key, value in iterable:
            self = self.put(key, value)
        return self

    def __getitem__(self, key):
        """Return the value associated with the key"""
        closest_node, *_ = self.descend(self.key2prefix(key))
        try:
            if closest_node.key == key:
                return closest_node.value
        except AttributeError:
            pass
        raise KeyError(key)

    def __contains__(self, key):
        raise NotImplementedError

    def __len__(self):
        raise NotImplementedError

    def __iter__(self):
        yield from self.keys()

    def items(self):
        for (key, value) in zip(self.keys(), self.values()):
            yield (key, value)

    def keys(self):
        raise NotImplementedError
    def values(self):
        raise NotImplementedError

    def put(self, key, value):
        """Set key to value

        Returns a new tree with that key set.
        """
        # Guaranteed to end up creating a new leaf node, so do that now.
        new_leaf = self.LeafNodeClass(key, value)
        siblings = self.descend(new_leaf.prefix)
        closest_node = next(siblings) # guaranteed to succeed

        if closest_node.__class__ is self.EmptyNodeClass:
            # Was replaced
            return new_leaf

        else:
            # The two leaves are joined by an inner node
            new_tip = self.InnerNodeClass(new_leaf, closest_node)

            # And we rebuild the inner nodes along the path from the siblings
            for sibling in siblings:
                new_tip = self.InnerNodeClass(new_tip, sibling)

            return new_tip


    def remove(self, key):
        """Remove key from tree

        Returns a new tree with that key removed.
        """
        # Guaranteed to end up creating a new leaf node, so do that now.
        siblings = self.descend(self.key2prefix(key))
        closest_node = next(siblings) # guaranteed to succeed

        if closest_node.__class__ is self.LeafNodeClass:
            # Ended up at a leaf node; is this the key we were looking for?
            if closest_node.key == key:
                # Yes! Remove and rebuild tree.
                try:
                    new_tip = next(siblings)
                except StopIteration:
                    return self.EmptyNodeClass()

                for sibling in siblings:
                    assert sibling.__class__ is not self.EmptyNodeClass
                    new_tip = self.InnerNodeClass(new_tip, sibling)

                return new_tip

        raise KeyError(key)

    def descend(self, prefix):
        """Descend into the tree

        Yields a depth first path along the specified prefix of the sibling
        nodes *not* visited during the descent, as well as the node that the
        descent terminated in.
        """
        raise NotImplementedError

    def _MerbinnerTree__issubset(self, them):
        """Implementation of issubset()

        It's guaranteed that self != them, and them is not pruned. Also
        typechecking is done for you.
        """
        raise NotImplementedError

    def issubset(self, other):
        """Report whether this tree is a subset of other

        Returns true if for every k:v in self other[k] == v, or in code:

            for k, v in self.items():
                if k not in other or other[k] != v:
                    return False
            return True
        """
        if other.__class__.__base__ is not self.__class__.__base__:
            raise TypeError('other must be of same class as self to compute issubset()')

        if self == other:
            return True

        elif other == self.EmptyNodeClass():
            # Nothing is a subset of nothing, except nothing, which the above
            # handles.
            return False

        # FIXME check that other is not pruned
        else:
            return self._MerbinnerTree__issubset(other)

def make_MerbinnerTree_subclass(subclass):
    @subclass.declare_union_subclass
    class MerbinnerTreeEmptyNodeClass(subclass):
        """The empty node"""
        SUB_HASHTAG = proofmarshal.proof.HashTag('ca380e10-c7d5-44df-aef0-55bce2125329')

        __slots__ = []
        SERIALIZED_ATTRS = []

        prefix = Bits()

        __instance = None
        def __new__(cls):
            if cls.__instance is not None:
                return cls.__instance
            else:
                singleton = proofmarshal.proof.ProofUnion.__new__(cls)
                cls.__instance = singleton
                return singleton

        def __len__(self):
            return 0

        def keys(self):
            yield from ()

        def values(self):
            yield from ()

        def descend(self, prefix):
            yield self

        def _MerbinnerTree__issubset(self, other):
            # Nothing is a subset of anything
            return True


    subclass.EmptyNodeClass = MerbinnerTreeEmptyNodeClass

    @subclass.declare_union_subclass
    class MerbinnerTreeLeafNode(subclass):
        """Leaf node"""
        SUB_HASHTAG = proofmarshal.proof.HashTag('f5cc855e-9d21-4f8d-ab42-7883c765c323')

        __slots__ = ['key','value']
        SERIALIZED_ATTRS = [('key',   subclass.KEY_SERIALIZER),
                            ('value', subclass.VALUE_SERIALIZER)]

        @property
        def prefix(self):
            return self.key2prefix(self.key)

        def __new__(cls, key, value):
            """Create a merbinner tree leaf node"""
            return proofmarshal.proof.ProofUnion.__new__(cls, key=key, value=value)

        def __len__(self):
            return 1

        def keys(self):
            yield self.key

        def values(self):
            yield self.value

        def descend(self, prefix):
            yield self

        def _MerbinnerTree__issubset(self, other):
            try:
                other_value = other[self.key]
            except KeyError:
                return False
            return self.value == other_value

    subclass.LeafNodeClass = MerbinnerTreeLeafNode

    @subclass.declare_union_subclass
    class MerbinnerTreeInnerNode(subclass):
        """Inner node, contains two children"""
        SUB_HASHTAG = proofmarshal.proof.HashTag('66d74741-0ffd-4178-9a79-641a45e23dda')

        __slots__ = ['left','right','prefix']
        SERIALIZED_ATTRS = [('prefix', BitsSerializer),
                            ('left',  subclass),
                            ('right', subclass)]

        def __new__(cls, first, second):
            """Create a merbinner tree leaf node

            first and second are put in left/right order for you.
            """
            if not (isinstance(first, subclass) and isinstance(second, subclass)):
                raise TypeError('First and second must be merbinner tree nodes')

            # If the prefixes are the same, there's something rather wrong.
            assert first.prefix != second.prefix

            prefix = first.prefix.common_prefix(second.prefix)

            # Both first and second must have prefixes more specific than us.
            assert (len(prefix) < len(first.prefix)) and (len(prefix) <= len(second.prefix))

            # Since they are more specific, we can determine the left/right
            # order by the next bit after us.
            left,right = (first,second) if second.prefix[len(prefix)] else (second, first)

            return proofmarshal.proof.ProofUnion.__new__(cls, left=left, right=right, prefix=prefix)

        def __len__(self):
            return len(self.left) + len(self.right)

        def keys(self):
            yield from self.left.keys()
            yield from self.right.keys()

        def values(self):
            yield from self.left.values()
            yield from self.right.values()

        def descend(self, prefix):
            if len(self.prefix) <= len(prefix) and prefix.startswith(self.prefix):
                # Prefix is both more specific than us (longer) and also starts
                # with us.
                #
                # Descend into matching child first, then yield its sibling.
                if prefix[len(self.prefix)]:
                    yield from self.right.descend(prefix)
                    yield self.left
                else:
                    yield from self.left.descend(prefix)
                    yield self.right
            else:
                # Prefix either ends at us, or not a match, so yield us as the
                # closest match, terminating the descent.
                yield self

        def _MerbinnerTree__issubset(self, them):
            if self == them:
                return True

            elif self.prefix == them.prefix:
                # We both have the same prefix, yet we're not the same node. We
                # can only be a subset of them if both our left and right
                # children are subsets of their left and right children,
                # respectively.
                assert them.__class__ is self.__class__
                assert not (self.left == them.left and self.right == them.right)

                # FIXME: depend correctly
                return (self.left.issubset(them.left) and self.right.issubset(them.right))

            elif self.prefix.startswith(them.prefix):
                assert len(them.prefix) < len(self.prefix)

                # We start with them, and are more specific than them, so
                # either their left or right side may contain trees that are a
                # subset of us.
                #
                # Try issubset() recursively on the left or right side as
                # appropriate to go deeper into the tree until we reach a
                # level with the same specificity.
                if self.prefix[len(them.prefix)]:
                    return self._MerbinnerTree__issubset(them.right)
                else:
                    return self._MerbinnerTree__issubset(them.left)

            else:
                # We don't share the same prefix, nor do we start with them, so
                # there's no way we're a subset.
                return False

    subclass.InnerNodeClass = MerbinnerTreeInnerNode

    return subclass

# Copyright (C) 2015 Peter Todd <pete@petertodd.org>
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


"""(Summed) Merkle Mountain Range support

Motivation
==========

We have a (potentially empty) list of message digests D = {d_0 ... d_n}. The
set may contain duplicate digests, given i != j it is valid for D[i] == D[j].
We wish to hash that list into a single commitment MMR(D) and with that
commitment prove the following efficiently in both time and space:

1) Inclusion of a single digest, given MMR(D) and d prove d ∈ D

2) What digest is at a given position, given MMR(D) and i prove D[i] = d

3) List length. Given MMR(D) prove Length(D). Similarly prove that D[i]
   does not exist given MMR(D)

4) Modification of digests in the list. Given MMR(D) where d ∈ D at position i
   prove that changing d to d' results in MMR(D')

We also want to be able to efficiently combine proofs together, proving
multiple statments with a single data structure. In particular:

5) Common prefixes. Given D_n = {d_0 ... d_n} and D_m = {d_0 ... d_n ... d_m}
   show that MMR(D_n) is a prefix of MMR(D_m)

It must not be possible to create pairs of contradictory proofs even for fake
commitments, however it is permissible for there to exist "valid" proofs for
fake commitments.

Concretely suppose we have a fake commitment M such that there exists no D for
which MMR(D) = M. It is permissible if there exists a proof P for which the
proof verification function returns true for the statement D[i] = d, where D is
the list M claims to commit too. However there must not exist a contradictory
proof P' for which the proof verification function returns true for the
statement M[i] = d', where d != d'

Similarly the also must not exist a proof P' for which the proof verification
function returns true for the statement Length(D) = j, where j < i-1, as that
would imply D has a item at an index beyond the length of the list.


Informal description
====================

As digests are accumulated we hash them into perfect binary trees, building up
the largest perfect binary trees possible as we go. At least one tree will
always exist with 2^k digests and the base, and 2^(k+1)-1 total elements. If
the total number of digests does not divide up into one perfect tree, more than
one tree will exist. For instance after accumulating 14 digests:

       /\
      /  \
     /\  /\  /\
    /\/\/\/\/\/\/\

The digests are divided into three perfect "mountains" of containing 8, 4, and
2 digests respectively. Next we take the list of mountain peaks and apply the
algorithm again:


         /\
        /  \
       /\   \
      /  \   \
     /\  /\  /\
    /\/\/\/\/\/\/\

Resulting in two peaks. We repeat until we are left with a single peak:

          /\
         /\ \
        /  \ \
       /\   \ \
      /  \   \ \
     /\  /\  /\ \
    /\/\/\/\/\/\/\

Here's an example with 62 digests in 5 mountains containing 32, 16, 8, 4, and 2
digests respectively:

                                  /\
                                 /\ \
                                /  \ \
                               /    \ \
                              /      \ \
                             /        \ \
                            /          \ \
                           /\           \ \
                          /  \           \ \
                         /    \           \ \
                        /      \           \ \
                       /        \           \ \
                      /          \           \ \
                     /            \           \ \
                    /              \           \ \
                   /\               \           \ \
                  /  \               \           \ \
                 /    \               \           \ \
                /      \               \           \ \
               /        \               \           \ \
              /          \               \           \ \
             /            \               \           \ \
            /              \               \           \ \
           /\              /\              /\           \ \
          /  \            /  \            /  \           \ \
         /    \          /    \          /    \          /\ \
        /      \        /      \        /      \        /  \ \
       /\      /\      /\      /\      /\      /\      /\   \ \
      /  \    /  \    /  \    /  \    /  \    /  \    /  \   \ \
     /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\  /\ \
    /\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\

As nodes in the mountains never change appending new items to an existing tree
is a cheap operation; only the tree committing to the peaks of the mountains
needs to be modified, given us O(log n) scaling. Similarly proofs of inclusion
are dominated by the largest mountain, again giving us O(log n) scaling.
Interestingly as the construction is right-associative, the lower bound is
simply Ω(1) for the most recently included items.


Proving position
================

While the above is suffient to prove inclusion of digests in an MMR, proving
the position of digests in the MMR, or length of the MMR, is more involved. One
solution would be for proofs of index and length statements to include all
peaks of the mountains in the MMR along with the height of those peaks. However
this solution leads to quite complex proof logic, and a distinction between
inner nodes within mountains and the inner nodes above mountain peaks.

Instead we simply have every inner node include in the hash calculation the
total number of digests under it. While this does increase the size of proofs
in some circumstances, it greatly simplifies the logic required to validate
those proofs, clearly preventing the creation of contradictory proofs.


Simplified formal construction
==============================

The hash of an empty list is:

    MMR({}) = H(0)

The hash of a list with one entry (also known as a leaf hash) is:

    MMR({d_0}) = H(1 || d_0)

For n > 1, let k be the smallest power of two such that k < n and n & k == k,
or if no such power of two exists, n / 2, where & is a bit-wise AND. The MMR of
of an n-element list D[n] is then defined recursively as:

    MMR(D[n]) = H(n || MMR(D[0:n-k]) || MMR(D[n-k:n]))

FIXME: RFC6962 says "Note that the hash calculations for leaves and nodes
differ. This domain separation is required to give second preimage
resistance." - how exactly does that apply here?


Informal proof of proof non-contradiction
=========================================

All MMR proofs are constructed recursively by visitng subsets of the total MMR.
Nodes not visited in the construction of the proof are replaced by hashes, a
process known as "pruning" The process of verifying a proof is similar, with
the additional step for each inner node visited the following two invarients
are checked:


1) 


As multiple digests of the same value are allowed in the MMR, the only class of
statements that can be contradictory are statements about the position of items
in the MMR, and statements about the overall length of the MMR.



As every node in the MMR commits to the total length, we can immediately rule out any contradictions between 

For there to exist two proofs P and P' that prove contradictory statements there must exist two 




"""

class MerkleMountainRange(proofmarshal.proof.ProofUnion):
    """Merkle Mountain Range"""
    __slots__ = []

    HASH_HMAC_KEY = None
    VALUE_SERIALIZER = None

    def __new__(cls, iterable=()):
       """Create a new merkle mountain range"""

       self = cls.EmptyNodeClass()
       return self.extend(iterable)

    def __len__(self):
        raise NotImplementedError

    def __getitem__(self, idx):
        raise NotImplementedError

    def __iter__(self):
        raise NotImplementedError

    def __reversed__(self):
        raise NotImplementedError

    def __setitem__(self, idx, value):
        # FIXME: give other way to do it
        raise TypeError('MerkleMountainRanges are immutable')

    def __delitem__(self, idx):
        # FIXME: give other way to do it
        raise TypeError('MerkleMountainRanges are immutable')

    def append(self, value):
        """Append object to end of MMR

        Returns a new MMR instance.
        """
        return self.LeafNodeClass(value)

    def extend(self, values):
        """Extend MMR from an iterable

        Returns a new MMR instance.
        """
        r = self
        for value in values:
            r = r.append(value)

        return r

    def __repr__(self):
        # Why __base__? Because this will be called in subclasses, and we want
        # to represent a MMR with the base class name, which will in turn be a
        # subclass of this class.
        assert self.__class__.__base__.__base__ is MerkleMountainRange
        return '%s(%r)' % (self.__class__.__base__.__qualname__, list(self))

    def is_perfect_tree(self):
        """Returns true if the tree's length is a power of two"""
        l = len(self)
        if not l:
            return False # exists no x such that 2**x = 0
        while not l & 1:
            l >>= 1
        return not (l & ~1)


def make_mmr_subclass(subclass):
    @subclass.declare_union_subclass
    class MerkleMountainRangeEmptyNode(subclass):
        """Empty node"""
        __slots__ = []

        SERIALIZED_ATTRS = []

        __instance = None
        def __new__(cls):
            if cls.__instance is not None:
                return cls.__instance
            else:
                singleton = subclass.__base__.__base__.__new__(cls)
                cls.__instance = singleton
                return singleton

        def __len__(self):
            return 0

        def __getitem__(self, idx):
            if isinstance(idx, int):
                raise IndexError('index out of range')

            elif isinstance(idx, slice):
                # A slice of an empty object does nothing. But call indices
                # first to raise TypeError if needed.
                idx.indices(0)
                return self

            else:
                raise TypeError('expected int or slice; got %r' % idx.__class__)

        def __iter__(self):
            yield from ()

        def __reversed__(self):
            yield from ()

        def append(self, value):
            """Append object to end of MMR

            Returns a new MMR instance.
            """
            return self.LeafNodeClass(value)

    subclass.EmptyNodeClass = MerkleMountainRangeEmptyNode

    @subclass.declare_union_subclass
    class MerkleMountainRangeLeafNode(subclass):
        """Inner node"""
        __slots__ = ['value']

        SERIALIZED_ATTRS = [('value', subclass.VALUE_SERIALIZER)]

        def __new__(cls, value):
            return subclass.__base__.__base__.__new__(cls, value=value)

        def __len__(self):
            return 1

        def __getitem__(self, idx):
            if isinstance(idx, int):
                if idx == 0 or idx == -1:
                    return self.value

                else:
                    raise IndexError('index out of range')

            elif isinstance(idx, slice):
                (start, stop, step) = idx.indices(1)

                if step != 1:
                    raise NotImplementedError

                if start <= 0 and stop >= 1:
                    # We're within the slice range.
                    #
                    # Note how this operation *doesn't* actually depend on
                    # self.value
                    return self

                else:
                    return self.EmptyNodeClass()

            else:
                raise TypeError('expected int or slice; got %r' % idx.__class__)

        def __iter__(self):
            yield self.value

        def __reversed__(self):
            yield self.value

        def append(self, new_value):
            """Append object to end of MMR

            Returns a new MMR instance.
            """
            right = self.LeafNodeClass(new_value)
            return self.InnerNodeClass(self, right)

    subclass.LeafNodeClass = MerkleMountainRangeLeafNode


    @subclass.declare_union_subclass
    class MerkleMountainRangeInnerNode(subclass):
        """Inner node"""
        __slots__ = ['left',  'right', 'length']

        SERIALIZED_ATTRS = [('left',  subclass),
                            ('right', subclass),
                            ('length', proofmarshal.serialize.UInt64)]

        def __new__(cls, left, right):
            length = len(left) + len(right)
            return subclass.__base__.__base__.__new__(cls, left=left, right=right, length=length)

        def __len__(self):
            return self.length

        def __getitem__(self, idx):
            if isinstance(idx, int):
                # convert negative indexes to positive
                if idx < 0:
                    idx = len(self) + idx

                # Out of bounds?
                if not (0 <= idx < len(self)):
                    raise IndexError('index out of range')

                if 0 <= idx < len(self.left):
                    return self.left[idx]

                if len(self.left) <= idx < len(self.left) + len(self.right):
                    return self.right[idx - len(self.left)]

                # should have been caught above
                assert False

            elif isinstance(idx, slice):
                (start, stop, step) = idx.indices(len(self))

                if step != 1:
                    raise NotImplementedError

                if start <= 0 and stop >= len(self):
                    # We satisfy the slice without modification, so return
                    # ourselves
                    return self

                if start < len(self.left):
                    # Left side satisfies at least part of the slice.
                    r = self.left[start:stop:step]

                    # Do we need part of the right side as well?
                    if stop > len(self.left):
                        offset = len(self.left)
                        r = r.extend(self.right[0:stop - offset:step])

                    return r

                if start >= len(self.left) and start < len(self):
                    # Right side satisfies at least part of the slice
                    offset = len(self.left)
                    return self.right[start - offset : stop - offset : step]

                else:
                    return self.EmptyNodeClass()

            else:
                raise TypeError('expected int or slice; got %r' % idx.__class__)

        def __iter__(self):
            yield from self.left
            yield from self.right

        def __reversed__(self):
            yield from reversed(self.right)
            yield from reversed(self.left)

        def _merge_trees(self, new_right):
            assert len(self) >= len(new_right)

            if not (len(self) & len(new_right)):
                # No trees of same height here and on the new right side, so
                # nothing needs to be merged.
                return self.InnerNodeClass(self, new_right)

            elif len(self) == len(new_right):
                # We're the exact same size as the tree to be merged, which means
                # we're both perfect trees. Return a perfect tree over both of us.
                assert(self.is_perfect_tree())
                return self.InnerNodeClass(self, new_right)

            else:
                # At least one tree on our right side needs merging.
                #
                # We can assert this, because if that was not true it would mean
                # only trees on the left side needed merging, which implies the
                # right side has fewer items in it than the tree to be merged.
                assert(len(self.right) & len(new_right))

                new_right = self.right._merge_trees(new_right)

                # Recurse on the left side.
                return self.left._merge_trees(new_right)

        def append(self, value):
            """Append object to end of MMR

            Returns a new MMR instance.
            """
            if len(self) & 1 == 0:
                # We have an even number of items. Adding another won't create a
                # new perfect tree anywhere, so we can leave ourselves unchanged
                # and return a new inner node over ourselves and the new item.
                #
                # Note how this also covers the case where we are a perfect tree.
                return self.InnerNodeClass(self, self.LeafNodeClass(value))

            else:
                # Odd number of items. At least one new perfect tree will be
                # created.
                new_right = self.right.append(value)

                # Merge trees
                return self.left._merge_trees(new_right)

    subclass.InnerNodeClass = MerkleMountainRangeInnerNode

    return subclass

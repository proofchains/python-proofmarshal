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

import binascii
import collections
import copy
import hashlib

from proofmarshal.serialize import Digest, HashingSerializer, BytesSerializationContext, SerializerTypeError, HashTag

from proofmarshal.bits import Bits, BitsSerializer
from proofmarshal.serialize import UInt8

"""Proof representation

Provides Proof and PrunedProof classes to represent complex, immutable,
cryptographic proofs that may have dependent proofs pruned away. Proofs have
cryptographically secure hashes, which commit to the facts proven by the proof,
as well as the facts used to prove those facts. Finally proofs can be pruned,
leaving a subset of data that is only capable of proving certain facts.

"""

class PrunedError(Exception):
    def __init__(self, attr_name, instance):
        self.attr_name = attr_name
        self.instance = instance
        super().__init__('Attribute %r not available, pruned away.' % attr_name)

class proof_result:
    def __init__(self, func, name=None):
        self.func = func

        self.name = name
        if self.name is None:
            assert self.func.__name__.startswith('__calc_result_')
            self.name = self.func.__name__[len('__calc_result_'):]

    def __call__(self, instance_self):
        print('calculating result %s on %r' % (self.name, instance_self))
        return self.func(instance_self)

def declare_proof_class(cls):
    # Start with the set of all active axioms from our base class.
    active_axioms = getattr(cls.__base__, 'ACTIVE_AXIOMS', collections.OrderedDict()).copy()

    # Replace previously defined axioms with results declared in this class.
    cls.RESULTS_BY_NAME = getattr(cls.__base__, 'RESULTS_BY_NAME', {}).copy()

    for result in cls.__dict__.values():
        if isinstance(result, proof_result):
            cls.RESULTS_BY_NAME[result.name] = result
            active_axioms.pop(result.name, None)

    # Special case for __inner_hash, as a result calculator needs to be added
    # for every subclass.
    if active_axioms:
        prev_axiom_class = tuple(cls.ACTIVE_AXIOMS_BY_CLASS.keys())[-1]
        result = proof_result(cls._calc__inner_hash, '_%s__inner_hash' % prev_axiom_class.__name__)

        cls.RESULTS_BY_NAME[result.name] = result
        del active_axioms[result.name] # if this doesn't succeed, something is wrong!


    # Add new axioms to the set of active axioms
    for axiom_name, axiom_type in cls.AXIOMS:
        if axiom_name == '__inner_hash':
            axiom_name = '_%s__inner_hash' % cls.__name__
        assert axiom_name not in active_axioms
        active_axioms[axiom_name] = axiom_type

    cls.ACTIVE_AXIOMS = active_axioms

    active_axioms_by_class = getattr(cls.__base__, 'ACTIVE_AXIOMS_BY_CLASS', collections.OrderedDict()).copy()
    active_axioms_by_class[cls] = cls.ACTIVE_AXIOMS
    cls.ACTIVE_AXIOMS_BY_CLASS = active_axioms_by_class
    return cls

@declare_proof_class
class Proof(HashingSerializer):
    """Base class for all proof objects

    Proofs use axioms to prove results. Proofs can be pruned, leaving a data
    structure with the results saved, while the axioms used to prove those
    results are discarded. Proofs can be subclassed; a subclass of a proof can
    replace some or all of the base class's axioms with results, or per-class
    constants.

    The most basic result - common to all Proofs - is the hash of the proof,
    which is calculated from the proof type and inner_hash. In a bare Proof
    class the type and inner_hash are both axioms; in subclasses the type is a
    per-class constant, and the inner_hash is a result calculated from the
    contents of the proof.

    """

    AXIOMS = [('__inner_hash', Digest)]

    def __getattr__(self, attr_name):
        try:
            orig_instance = object.__getattribute__(self, '_Proof__orig_instance')
        except AttributeError as err:
            # We are not pruned. This is either a calculatable result, or an
            # error.
            result_calc_func = self.RESULTS_BY_NAME.get(attr_name, None)
            if result_calc_func is not None:
                result = result_calc_func(self)
                object.__setattr__(self, attr_name, result)
                return result

            else:
                # FIXME: is this the best way to get a nice error message?
                object.__getattribute__(self, attr_name)

        else:
            # We are pruned. Get the value from the original instance.
            value = getattr(orig_instance, attr_name)

            if isinstance(value, Proof):
                value = value.prune()

            object.__setattr__(self, attr_name, value)

            # Record the pruning level.
            level = self.__class__
            while level is not self.__pruning_level:
                try:
                    if attr_name in level.__base__.ACTIVE_AXIOMS:
                        level = level.__base__
                    else:
                        break
                except AttributeError:
                    break

            self.__pruning_level = level

            return value

    @proof_result
    def __calc_result_hash(self) -> Digest:
        return self.HASHTAG(self.__inner_hash).digest()

    @classmethod
    def _calc__inner_hash(cls, self) -> Digest:
        print('_calc__inner_hash(%r, %r)' % (cls, self))
        hasher = hashlib.sha256()
        for axiom_name, axiom_class in cls.ACTIVE_AXIOMS.items():
            axiom_value = getattr(self, axiom_name)
            if issubclass(axiom_class, HashingSerializer):
                hasher.update(axiom_class.get_hash(axiom_value))

            else:
                hasher.update(axiom_class.serialize(axiom_value))

        return hasher.digest()

    def prune(self):
        """Create a pruned version of this prooF

        Returns a new instance with all results and axioms removed. A reference
        to the original instance is maintained, and used to determine what
        axioms are needed.
        """

        pruned_self = object.__new__(self.__class__)

        object.__setattr__(pruned_self, '_Proof__orig_instance', self)
        object.__setattr__(pruned_self, '_Proof__pruning_level', Proof)
        return pruned_self

    def get_hash(self):
        return self.hash

class VarProof(Proof):
    """Proofs with multiple variants"""
    @proof_result
    def __calc_result_inner_hash(self) -> Digest:
        cls = self.__class__
        while cls.__base__ != BaseProof:
            cls = cls.__base__

        print('axiom class is %r' % cls)
        hasher = hashlib.sha256()
        for axiom_name, axiom_class in cls.ACTIVE_AXIOMS.items():
            axiom_value = getattr(self, axiom_name)
            if issubclass(axiom_class, HashingSerializer):
                hasher.update(axiom_class.get_hash(axiom_value))

            else:
                hasher.update(axiom_class.serialize(axiom_value))

        return hasher.digest()

@declare_proof_class
class Tree(Proof):
    HASHTAG = HashTag('21362f98-10d3-4f52-b13d-6355680413cd')
    AXIOMS = [('prefix', BitsSerializer),
              ('sum', UInt8),
              ('__inner_hash', Digest)]

    def __init__(self, prefix : Bits, sum : int):
        self.prefix = prefix
        self.sum = sum

    def __getitem__(self, prefix) -> int:
        raise NotImplementedError

@declare_proof_class
class LeafNode(Tree):
    AXIOMS = [('key', BitsSerializer),
              ('value', UInt8)]

    def __init__(self, key : Bits, value : int):
        self.key = key
        self.value = value

    @proof_result
    def __calc_result_sum(self) -> int:
        return self.value

    @proof_result
    def __calc_result_prefix(self) -> Bits:
        return self.key

    def __getitem__(self, prefix) -> int:
        return self.value

@declare_proof_class
class InnerNode(Tree):
    AXIOMS = [('left', Tree),
              ('right', Tree)]

    def __init__(self, left : Tree, right : Tree):
        self.left = left
        self.right = right

    @proof_result
    def __calc_result_sum(self) -> int:
        return self.left.sum + self.right.sum

    @proof_result
    def __calc_result_prefix(self) -> Bits:
        return Bits.common_prefix(self.left.prefix, self.right.prefix)

    def __getitem__(self, prefix) -> int:
        raise NotImplementedError

@declare_proof_class
class EmptyNode(Tree):
    AXIOMS = []

    def __init__(self):
        pass

    @proof_result
    def __calc_result_sum(self) -> int:
        return 0

    @proof_result
    def __calc_result_prefix(self) -> Bits:
        return Bits()

    def __getitem__(self, prefix) -> int:
        raise KeyError(prefix)

l00 = LeafNode(Bits([0,0]), 1)
l01 = LeafNode(Bits([0,1]), 3)

i0 = InnerNode(l00, l01)

i1 = InnerNode(LeafNode(Bits([1,0]), 5),
               LeafNode(Bits([1,1]), 7))

i = InnerNode(i0, i1)

ip = i.prune()

print(ip.hash)
print(ip.left.left.value)

import pdb; pdb.set_trace()

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
import copy
import hashlib

from proofmarshal.serialize import HashingSerializer, BytesSerializationContext, SerializerTypeError, HashTag

"""Proof representation

Provides Proof and PrunedProof classes to represent complex, immutable,
cryptographic proofs that may have dependent proofs pruned away.

"""

class PrunedError(Exception):
    def __init__(self, attr_name, instance):
        self.attr_name = attr_name
        self.instance = instance
        super().__init__('Attribute %r not available, pruned away.' % attr_name)

class Proof(HashingSerializer):
    """Base class for all proof objects

    Proofs are structures that support pruning, automatically track
    dependencies, and can be (partially) validated.

    """
    HASHTAG = None

    __slots__ = ['is_pruned', 'is_fully_pruned','__orig_instance','data_hash','hash']
    SERIALIZED_ATTRS = ()
    SERIALIZED_ATTRS_BY_NAME = None

    def __new__(cls, **kwargs):
        """Basic creation/initialization"""
        if cls.SERIALIZED_ATTRS_BY_NAME is None:
            cls.SERIALIZED_ATTRS_BY_NAME = {name:ser_cls for name, ser_cls in cls.SERIALIZED_ATTRS}

        is_pruned = False
        self = object.__new__(cls)
        for name, ser_cls in cls.SERIALIZED_ATTRS_BY_NAME.items():
            value = kwargs[name]
            ser_cls.check_instance(value)
            object.__setattr__(self, name, value)

            if issubclass(ser_cls, Proof):
                is_pruned |= value.is_pruned

        object.__setattr__(self, 'is_fully_pruned', False)
        object.__setattr__(self, 'is_pruned', is_pruned)
        object.__setattr__(self, '_Proof__orig_instance', None)
        return self

    @classmethod
    def check_instance(cls, instance):
        """Check that an instance can be serialized by this serializer

        Raises SerializerTypeError if not
        """
        # FIXME

    def __eq__(self, other):
        if isinstance(other, Proof):
            return self.hash == other.hash

        else:
            return NotImplemented

    def __hash__(self):
        # We could return self.hash directly, however that might cause problems
        # in cases where the Proof object has had some kind of PoW applied to
        # it to brute-force the hash.
        return hash(self.hash)

    def __setattr__(self, name, value):
        raise TypeError('%s instances are immutable' % self.__class__.__qualname__)

    def __delattr__(self, name):
        raise TypeError('%s instances are immutable' % self.__class__.__qualname__)

    def prune(self):
        """Create a pruned version of this proof

        Returns a new instance with all attributes removed. A reference to the
        original instance is maintained, and used to unprune attributes as they
        are used.
        """

        # Start with a blank instance with absolutely no attributes set at all.
        pruned_self = object.__new__(self.__class__)

        object.__setattr__(pruned_self, '_Proof__orig_instance', self)
        object.__setattr__(pruned_self, 'is_fully_pruned', True)
        object.__setattr__(pruned_self, 'is_pruned', True)

        return pruned_self

    def __getattr__(self, name):
        # Special-case (data)_hash to let it be calculated lazily
        if name == 'data_hash':
            data_hash = self.calc_data_hash()
            object.__setattr__(self, 'data_hash', data_hash)
            return data_hash

        elif name == 'hash':
            hash = self.calc_hash()
            object.__setattr__(self, 'hash', hash)
            return hash

        if self.__orig_instance is None:
            # Don't have the original instance. Is this an attribute we should
            # have?
            if name in self.SERIALIZED_ATTRS_BY_NAME:
                # FIXME: raise pruning error
                raise PrunedError(name, self)
            else:
                raise AttributeError("%r object has no attribute %r" % (self.__class__, name))

        else:
            assert self.is_pruned

            # We are pruned. Try getting that attribute from the original,
            # non-pruned, instance. If it doesn't exist, the above code will throw
            # an exception as expected.
            value = getattr(self.__orig_instance, name)

            # If the value is itself a proof, prune it to track dependencies
            # recursively.
            if isinstance(value, Proof):
                value = value.prune()

            # For efficiency, we can now add that value to self to avoid going
            # through this process over again.
            object.__setattr__(self, name, value)

            # We succesfully brought something back into view, which means this
            # instance must not be fully pruned.
            object.__setattr__(self, 'is_fully_pruned', False)
            return value

    def calc_data_hash(self):
        if self.__orig_instance is not None:
            # Avoid unpruning unnecessarily
            return self.__orig_instance.data_hash

        else:
            # FIXME: catch pruning errors; should never happen
            hasher = hashlib.sha256()

            for attr_name, ser_cls in self.SERIALIZED_ATTRS:
                attr_value = getattr(self, attr_name)

                if issubclass(ser_cls, HashingSerializer):
                    hasher.update(ser_cls.get_hash(attr_value))

                else:
                    hasher.update(ser_cls.serialize(attr_value))

            return hasher.digest()

    def calc_hash(self):
        if self.__orig_instance is not None:
            # Avoid unpruning unnecessarily
            return self.__orig_instance.hash

        else:
            return self.HASHTAG(self.data_hash).digest()

    def get_hash(self):
        return self.hash

    def _ctx_serialize(self, ctx):
        for attr_name, ser_cls in self.SERIALIZED_ATTRS:
            attr = getattr(self, attr_name)
            ser_cls.ctx_serialize(attr, ctx)

    def ctx_serialize(self, ctx):
        if self.is_fully_pruned:
            ctx.write_bool(True)
            ctx.write_bytes(self.data_hash)

        else:
            ctx.write_bool(False)
            self._ctx_serialize(ctx)


    def serialize(self):
        """Serialize to bytes"""
        ctx = BytesSerializationContext()
        self.ctx_serialize(ctx)
        return ctx.getbytes()

    @classmethod
    def _ctx_deserialize(cls, ctx):
        kwargs = {}

        for name, ser_cls in cls.SERIALIZED_ATTRS:
            value = ser_cls.ctx_deserialize(ctx)
            kwargs[name] = value

        return Proof.__new__(cls, **kwargs)

    @classmethod
    def ctx_deserialize(cls, ctx):
        fully_pruned = ctx.read_bool()

        if fully_pruned:
            self = object.__new__(cls)

            data_hash = ctx.read_bytes(32) # FIXME
            object.__setattr__(self, 'data_hash', data_hash)

            object.__setattr__(self, 'is_fully_pruned', True)
            object.__setattr__(self, 'is_pruned', True)
            object.__setattr__(self, '_Proof__orig_instance', None)

            return self

        else:
            return cls._ctx_deserialize(ctx)

    def __repr__(self):
        # FIXME: better way to get a fully qualified name?
        return '%s.%s(<%s>)' % (self.__class__.__module__, self.__class__.__qualname__,
                                binascii.hexlify(self.hash).decode('utf8'))

class ProofUnion(Proof):
    """Serialization of unions of Proofs"""
    __slots__ = []

    UNION_CLASSES = None

    @classmethod
    def check_instance(cls, value):
        for cls in cls.UNION_CLASSES:
            if isinstance(value, cls):
                break
        else:
            raise SerializerTypeError('Class %r is not part of the %r union' % (value.__class__, cls))

    @classmethod
    def declare_union_subclass(cls, subclass):
        """Class decorator to make a subclass part of a ProofUnion

        The HASHTAG for the subclass will be derived from for you.
        """
        if not issubclass(subclass, ProofUnion):
            raise TypeError('Only ProofUnion subclasses can be part of a ProofUnion')

        if cls.UNION_CLASSES is None:
            cls.UNION_CLASSES = []

        subclass.HASHTAG = subclass.SUB_HASHTAG.derive(cls.HASHTAG)

        cls.UNION_CLASSES.append(subclass)

        return subclass

    def _ctx_serialize(self, ctx):
        for i,cls in enumerate(self.UNION_CLASSES):
            if isinstance(self, cls):
                ctx.write_varuint(i)
                break

        else:
            raise SerializerTypeError('bad class')

        super()._ctx_serialize(ctx)

    @classmethod
    def _ctx_deserialize(cls, ctx):
        i = ctx.read_varuint()

        try:
            union_cls = cls.UNION_CLASSES[i]
        except IndexError:
            # FIXME: nicer error message
            raise DeserializationError('bad union class number %d' % i)

        return super(ProofUnion, union_cls)._ctx_deserialize(ctx)

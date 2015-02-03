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

import proofmarshal.serialize

"""Proof representation

Provides Proof and PrunedProof classes to represent complex, immutable,
cryptographic proofs that may have dependent proofs pruned away.

"""

class Proof(proofmarshal.serialize.Serializable):
    """Base class for all proof objects

    Immutable!
    """
    __slots__ = ['hash','is_fully_immutable']

    def pruned(self):
        """Return a pruned version of this proof

        Returns a new, pruned, instance with all (prunable) proof attributes
        replaced with PrunedProof's
        """
        kwargs = {}
        for name, ser_class in self.SERIALIZED_ATTRS:
            value = getattr(self, name)
            kwargs[name] = PrunedProof(value.hash, value) if issubclass(ser_class, MaybePruned) else value

        return Proof.__new__(self.__class__, **kwargs)

    def depend(self, *attrs):
        """Mark a dependency on one or more attributes, unpruning if necessary.

        Modifies self in place.
        """
        for attr_path in attrs:
            attr_name, *rest = attr_path.split('.')

            attr_value = getattr(self, attr_name)

            if isinstance(attr_value, PrunedProof):
                if attr_value.orig_instance is None:
                    raise Exception("Pruned! Attribute %s not available; can't depend on it" % attr_value)

                else:
                    attr_value = attr_value.orig_instance.pruned()
                    object.__setattr__(self, attr_name, attr_value)

            if isinstance(attr_value, Proof):
                attr_value.depend(*rest)

    def __hash__(self):
        return hash(self.hash)

    def __eq__(self, other):
        if isinstance(other, Proof):
            return self.hash == other.hash
        else:
            return False

    def __repr__(self):
        # FIXME: better way to get a fully qualified name?
        return '%s.%s(<%s>)' % (self.__class__.__module__, self.__class__.__qualname__,
                                binascii.hexlify(self.hash).decode('utf8'))


class ProofUnion(Proof):
    """Proofs with more than one possible class"""
    __slots__ = []

    UNION_CLASSES = None

    @classmethod
    def check_instance(cls, value):
        if value.__class__ in cls.UNION_CLASSES:
            # FIXME
            pass

        else:
            raise Exception('FIXME')


    @classmethod
    def ctx_serialize(cls, value, ctx):
        union_classes = {cls:i for i,cls in enumerate(cls.UNION_CLASSES)}
        ctx.write_varuint(union_classes[value.__class__])
        super(Proof, value.__class__).ctx_serialize(value, ctx)

    @classmethod
    def ctx_deserialize(cls, ctx):
        self = object.__new__(cls)

        for name, ser_cls in cls.SERIALIZED_ATTRS:
            value = ser_cls.ctx_deserialize(ctx)

            object.__setattr__(self, name, value)

        return self


class PrunedProof(Proof):
    """A proof that has been pruned

    Only the hash of the proof is guaranteed available. The original instance
    from which this PrunedProof was derived from may also be available in the
    orig_instance attribute.

    """
    __slots__ = ['hash','orig_instance']

    SERIALIZED_ATTRS = [('hash',proofmarshal.serialize.Digest)]

    def __new__(cls, hash, orig_instance=None):
        self = object.__new__(cls)
        object.__setattr__(self, 'hash', hash)
        object.__setattr__(self, 'orig_instance', orig_instance)
        object.__setattr__(self, 'is_fully_immutable', True)
        return self

    @classmethod
    def from_proof(cls, proof):
        """Create a pruned proof from an existing proof"""
        return cls(proof.hash, proof)

    def prune(self):
        return self

    def calc_hash(self):
        raise TypeError('Proof is pruned; nothing to calculate the hash from')

    def depend(self, *attrs):
        if len(attrs):
            raise Exception('pruned')

class MaybePruned(proofmarshal.serialize.Serializer):
    """Serializer for proofs that might be pruned away"""

    PROOF_CLASSES = None

    def __new__(self, proof_class):
        class sub(MaybePruned):
            PROOF_CLASS = proof_class

        sub.__name__ = 'MaybePruned(%s)' % proof_class.__name__
        return sub

    @classmethod
    def calc_hash(cls, value):
        assert value.__class__ in (PrunedProof, cls.PROOF_CLASS)
        return value.hash

    @classmethod
    def check_instance(cls, value):
        if value.__class__ is PrunedProof:
            PrunedProof.check_instance(value)

        elif issubclass(value.__class__, cls.PROOF_CLASS):
            cls.PROOF_CLASS.check_instance(value)

        else:
            raise NotImplementedError('FIXME')

    @classmethod
    def ctx_serialize(cls, value, ctx):
        if value.__class__ is PrunedProof:
            ctx.write_bytes(b'\x00')
            PrunedProof.ctx_serialize(value, ctx)

        else:
            ctx.write_bytes(b'\x01')
            cls.PROOF_CLASS.ctx_serialize(value, ctx)

    @classmethod
    def ctx_deserialize(cls, ctx):
        self = object.__new__(cls)

        for name, ser_cls in cls.SERIALIZED_ATTRS:
            value = ser_cls.ctx_deserialize(ctx)

            object.__setattr__(self, name, value)

        return self

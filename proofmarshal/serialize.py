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
import hashlib
import hmac
import io

"""Deterministic, (mostly)context-free, object (de)serialization, and hashing

Motivation
==========

Standard serialization libraries/formats aren't suitable for cryptographic
purposes as they rarely, if ever, support deterministic round-trip encoding.
They also fail to define a way to cryptographically hash the serialized data,
let alone recursively hash that data. Finally they are unable to handle
serialization of data whose structure is a DAG rather than a tree; they don't
efficiently support references to previously serialized data.


Basic grammar
=============

FixedBytes(n) - A fixed length byte array

uIntLEB128(max) - An unsigned, little-endian, base128, integer in the range 0 <= i < n

IntLEB128(min,max)  - Signed, little-endian, base128, integer in the range min < i < max

Struct - Zero or more of the above, (de)serialized in a fixed order to form a
         structure.

Serialization contexts
======================

We would like to be able to serialize/deserialize



Hashing
=======

Cryptographic hashing of serializable objects is performed by re-using the
serialization machinery. For efficiency reasons objects with serialized
representations that are less than the length of a hash return a so-called
"hash" that is simply the serialized object itself.


"""

DIGEST_LENGTH = 32

class DeserializationError(Exception):
    """Base class for all errors encountered during deserialization"""

class TruncationError(DeserializationError):
    """Truncated data encountered while deserializing"""


class SerializerTypeError(TypeError):
    """Wrong type for specified serializer"""

class SerializerValueError(ValueError):
    """Inappropriate value to be serialized (of correct type)"""


class SerializationContext:
    """Context for serialization

    Allows multiple serialization targets to share the same codebase, for
    instance bytes, memoized serialization, hashing, etc.
    """

    def write_bool(self, value):
        """Write a bool"""
        raise NotImplementedError

    def write_varuint(self, value):
        """Write a variable-length unsigned integer"""
        raise NotImplementedError

    def write_bytes(self, value):
        """Write fixed-length bytes"""
        raise NotImplementedError

    def write_varbytes(self, value):
        """Write variable-length bytes"""
        raise NotImplementedError

    def write_obj(self, value, serialization_class=None):
        """Write a (memoizable/hashable) object

        The object *must* have the hash attribute.

        If serialization_class is specified, that class is used as the
        Serializer; otherwise value.__class__ is used.
        """
        raise NotImplementedError

class DeserializationContext:
    """Context for deserialization

    Allows multiple deserialization sources to share the same codebase, for
    instance bytes, memoized serialization, hashing, etc.
    """
    def read_bool(self):
        """Read a bool"""
        raise NotImplementedError

    def read_varuint(self, max_int):
        """Read a variable-length unsigned integer"""
        raise NotImplementedError

    def read_bytes(self, expected_length):
        """Read fixed-length bytes"""
        raise NotImplementedError

    def read_varbytes(self, value, max_length=None):
        """Read variable-length bytes

        No more than max_length bytes will be read.
        """
        raise NotImplementedError

    def read_obj(self, serialization_class):
        """Read a (potentially memoizable/hashable) object"""
        raise NotImplementedError


class StreamSerializationContext(SerializationContext):
    def __init__(self, fd):
        """Serialize to a stream"""
        self.fd = fd

    def write_bool(self, value):
        # unsigned little-endian base128 format (LEB128)
        if value is True:
            self.fd.write(b'\xff')

        elif value is False:
            self.fd.write(b'\x00')

        else:
            raise TypeError('Expected bool; got %r' % value.__class__)

    def write_varuint(self, value):
        # unsigned little-endian base128 format (LEB128)
        if value == 0:
            self.fd.write(b'\x00')

        else:
            while value != 0:
                b = value & 0b01111111
                if value > 0b01111111:
                    b |= 0b10000000
                self.fd.write(bytes([b]))
                if value <= 0b01111111:
                    break
                value >>= 7

    def write_bytes(self, value):
        self.fd.write(value)

    def write_obj(self, value, serialization_class=None):
        if serialization_class is None:
            serialization_class = value.__class__
        serialization_class.ctx_serialize(value, self)

class StreamDeserializationContext(DeserializationContext):
    def __init__(self, fd):
        """Deserialize from a stream"""
        self.fd = fd

    def fd_read(self, l):
        r = self.fd.read(l)
        if len(r) != l:
            raise DataTruncatedError('Tried to read %d bytes but got only %d bytes' % \
                                        (l, len(r)))
        return r

    def read_bool(self):
        # unsigned little-endian base128 format (LEB128)
        b = self.fd_read(1)[0]
        if b == 0xff:
            return True

        elif b == 0x00:
            return False

        else:
            raise DeserializationError('read_bool() expected 0xff or 0x00; got %d' % b)

    def read_varuint(self):
        value = 0
        shift = 0

        while True:
            b = self.fd_read(1)[0]
            value |= (b & 0b01111111) << shift
            if not (b & 0b10000000):
                break
            shift += 7

        return value

    def read_bytes(self, expected_length=None):
        if expected_length is None:
            expected_length = self.read_varuint(None)
        return self.fd_read(expected_length)

    def read_obj(self, serialization_class):
        return serialization_class.ctx_deserialize(self)

class BytesSerializationContext(StreamSerializationContext):
    def __init__(self):
        """Serialize to bytes"""
        super().__init__(io.BytesIO())

    def getbytes(self):
        """Return the bytes serialized to date"""
        return self.fd.getvalue()

class BytesDeserializationContext(StreamDeserializationContext):
    def __init__(self, buf):
        """Deserialize from bytes"""
        super().__init__(io.BytesIO(buf))

    # FIXME: need to check that there isn't extra crap at end of object

class Serializer:
    """(De)serialize an instance of a class

    Base class for all serialization classes. The actual serialization is
    performed by serialization *instances*, not classes, and an instance may be
    its own serializer.
    """
    __slots__ = []


    @classmethod
    def check_instance(cls, instance):
        """Check that an instance can be serialized by this serializer

        Raises SerializerTypeError if the instance class is not the expected
        class, and SerializerValueError if the class is correct, but the actual
        value is incorrect. (e.g. an out of range integer)
        """
        raise NotImplementedError

    @classmethod
    def ctx_serialize(cls, self, ctx):
        """Serialize to a context"""
        raise NotImplementedError

    @classmethod
    def ctx_deserialize(cls, ctx):
        """Deserialize from a context"""
        raise NotImplementedError

    @classmethod
    def serialize(cls, self):
        """Serialize to bytes"""
        ctx = BytesSerializationContext()
        cls.ctx_serialize(self, ctx)
        return ctx.getbytes()

    @classmethod
    def deserialize(cls, serialized_value):
        """Deserialize from bytes"""
        ctx = BytesDeserializationContext(serialized_value)
        r = cls.ctx_deserialize(ctx)
        # FIXME: check for junk at end
        return r

class SerBool(Serializer):
    """Serialization of boolean values"""
    @classmethod
    def check_instance(cls, value):
        if value.__class__ is not bool:
            raise SerializerTypeError('Expected bool; got %r' % value.__class__)

    @classmethod
    def ctx_serialize(cls, self, ctx):
        ctx.write_bool(self)

    @classmethod
    def ctx_deserialize(cls, ctx):
        return ctx.read_bool()

class FixedBytes(Serializer):
    """Serialization of fixed-length byte arrays"""
    EXPECTED_LENGTH = None

    def __new__(cls, expected_length):
        if expected_length.__class__ is not int:
            raise TypeError('Expected int; got %r' % expected_length.__class__.__qualname__)
        if expected_length < 0:
            raise ValueError('Expected length must be non-negative; got %d' % expected_length)

        # Slightly evil...
        class r(FixedBytes):
            EXPECTED_LENGTH = expected_length

        r.__name__ = 'FixedBytes(%d)' % expected_length
        return r

    @classmethod
    def check_instance(cls, value):
        if value.__class__ is not bytes:
            raise SerializerTypeError('Expected bytes; got %r' % value.__class__)

        if len(value) != cls.EXPECTED_LENGTH:
            raise SerializerValueError('Expected bytes to be of len %d; got %d' % (cls.EXPECTED_LENGTH, len(value)))

    @classmethod
    def ctx_serialize(cls, self, ctx):
        ctx.write_bytes(self)

    @classmethod
    def ctx_deserialize(cls, ctx):
        return ctx.read_bytes(cls.EXPECTED_LENGTH)

class Digest(FixedBytes):
    EXPECTED_LENGTH = DIGEST_LENGTH

class UInt(Serializer):
    """Serialization of unsigned integers"""
    @classmethod
    def check_instance(cls, value):
        if value.__class__ is not int:
            raise SerializerTypeError('Expected an int; got %r' % value.__class__)

        if not (0 <= value <= cls.MAX_INT):
            raise SerializerValueError('Integer out of range; 0 <= %d <= %d' % (value, cls.MAX_INT))

    @classmethod
    def ctx_serialize(cls, self, ctx):
        ctx.write_varuint(self)

    @classmethod
    def ctx_deserialize(cls, ctx):
        r = ctx.read_varuint()
        if not (0 <= r <= cls.MAX_INT):
            raise DeserializationError('Deserialized integer out of range; 0 <= %d <= %d' % (r, cls.MAX_INT))
        return r

class UInt8(UInt):
    MAX_INT = 2**8-1
class UInt16(UInt):
    MAX_INT = 2**16-1
class UInt32(UInt):
    MAX_INT = 2**32-1
class UInt64(UInt):
    MAX_INT = 2**64-1

class HashingSerializer(Serializer):
    """Serialization of objects with globally unique hashes

    In addition to (de)serialization, also provides calc_hash(), which returns
    the globally unique hash of the instance.

    By "globally unique", we mean that it is guaranteed no two instances exist
    with the same hash, even across different classes of instances, unless the
    instances themselves are equivalent.

    """
    HASH_HMAC_KEY = None

    @classmethod
    def get_hash(cls, obj):
        """Get the globally unique hash of an instance

        The hash may or may not have been calculated from scratch; a cached
        hash may be returned in which case memory corruption or some other
        error may result in an incorrect hash.
        """
        raise NotImplementedError('get_hash() not implemented for %r' % cls)

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

import functools
import hashlib
import hmac
import operator

import proofmarshal.serialize

@functools.total_ordering
class Bits:
    """Immutable array of bits"""

    __slots__ = ['__length', '__buf']

    def __new__(cls, iterable=None):
        """Construct immutable array of bits from an iterable"""
        if iterable is None:
            try:
                return cls.__empty_Bits_singleton
            except AttributeError:
                self = object().__new__(cls)
                self.__length = 0
                self.__buf = b''
                cls.__empty_Bits_singleton = self
                return self

        elif iterable.__class__ is Bits:
            return iterable

        else:
            buf = []
            byte = 0
            length = 0
            for bit in iterable:
                bit = bool(bit)
                byte |= bit << (7 - (length % 8))

                length += 1
                if length % 8 == 0:
                    buf.append(byte)
                    byte = 0
            buf.append(byte)

            if length:
                self = object().__new__(cls)
                self.__length = length
                self.__buf = bytes(buf)
                return self

            else:
                return Bits()

    def __repr__(self):
        return '%s([%s])' % (self.__class__.__qualname__,
                             ",".join(['1' if bit else '0' for bit in self]))

    @classmethod
    def from_bytes(cls, buf, length=None):
        """Create bits from bytes

        length - Length in bits (if not len(buf)*8)

        Note that internally the provided bytes will be reused; a new copy will
        not be created.
        """
        if buf.__class__ is not bytes:
            raise TypeError('Expected bytes instance; got %s' % buf.__class__.__qualname__)

        if length is None:
            length = len(buf)*8

        if length.__class__ is not int:
            raise TypeError('Expected int length; got %s' % length.__class__.__qualname__)
        if length < 0:
            raise ValueError('Length must be non-negative int')
        if len(buf) * 8 < length:
            raise ValueError('Length longer than bits in buf')

        self = object().__new__(cls)
        self.__length = length
        self.__buf = buf if length else b''
        return self

    def __iter__(self):
        for i in range(self.__length):
            yield (self.__buf[i // 8] >> (7 - i % 8)) & 0b1

    def __len__(self):
        return self.__length

    def __full_width_prefix(self):
        """Return the part of the buf with full-width bytes"""
        return self.__buf[0:self.__length // 8]

    def __tail_bits(self):
        """Return the non-full-width tail, with unused bits masked to zero"""
        odd_bits = self.__length % 8
        if odd_bits:
            return self.__buf[self.__length // 8] & (0xFF << (8 - odd_bits))

        else:
            return 0

    def __eq__(self, rhs):
        if self.__class__ is not rhs.__class__:
            return NotImplemented

        if self.__length != rhs.__length:
            return False

        else:
            # Lengths are identical. If the buffers are the same, we're done.
            if self.__full_width_prefix() != rhs.__full_width_prefix():
                return False
            else:
                return self.__tail_bits() == rhs.__tail_bits()

    def __lt__(self, rhs):
        if self.__class__ is not rhs.__class__:
            return NotImplemented

        self_fwp = self.__full_width_prefix()
        rhs_fwp = rhs.__full_width_prefix()
        if self_fwp < rhs_fwp:
            return True

        elif self_fwp == rhs_fwp:
            return self.__tail_bits() < rhs.__tail_bits()

        else:
            return False


    def __getitem__(self, idx):
        if isinstance(idx, int):
            if idx < 0:
                idx = self.__length + idx

            if not (0 <= idx < self.__length):
                raise IndexError('Bits index out of range')

            return (self.__buf[idx // 8] >> (7 - idx % 8)) & 0b1

        elif isinstance(idx, slice):
            start, stop, step = idx.indices(self.__length)

            # We can reuse self.__buf if the slice starts at index zero and has a standard step
            if step == 1 and start == 0:
                if stop == 0:
                    return self.__class__()

                elif stop == self.__length:
                    return self

                else:
                    r = super().__new__(self.__class__)
                    r.__length = stop
                    r.__buf = self.__buf
                    return r

            else:
                # Fallback implementation; user is doing something odd
                return self.__class__(tuple(self)[idx])


        else:
            raise TypeError('Bits indices must be integers, not %r' % idx.__class__)

    def __add__(self, rhs):
        if self.__class__ is not rhs.__class__:
            raise TypeError("Can't concatenate %s to %s" % (self.__class__.__qualname__, rhs.__class__.__qualname__))

        # Fast-path: one or the other side is of zero-length
        if not self.__length:
            return rhs
        elif not rhs.__length:
            return self

        else:
            # Do we need to shift the bits of the right-hand-side before we concatenate it to our buffer?
            rhs_offset = self.__length % 8
            rhs_buf = rhs.__buf
            if rhs_offset:
                # Because we have an offset subsequent bytes need to be
                # "merged" together in pairs.
                rhs_buf = []

                # Init the tail bits from the tail of the lhs
                tail_bits = self.__buf[self.__length // 8] & (0xFF << (8 - self.__length % 8))

                # For every byte in the RHS
                for byte in rhs.__buf[0:rhs.__length // 8 + (1 if rhs.__length % 8 else 0)]:
                    # For every byte on the rhs, shift it's MSB's right by the
                    # offset, and or it with the tail bits.
                    rhs_buf.append(tail_bits | (byte >> rhs_offset))

                    # Then save LSB's as the new tail bits, shifted to the
                    # left the amount of the offset
                    tail_bits = (byte << (8 - rhs_offset)) & 0xFF

                # Last tail bits get saved
                rhs_buf.append(tail_bits)
                rhs_buf = bytes(rhs_buf)

            r = super().__new__(self.__class__)
            r.__length = self.__length + rhs.__length
            r.__buf = self.__buf[0:self.__length // 8] + rhs_buf
            return r

    def __invert__(self):
        # Technically we should check types of self, but... yeah.

        if not self.__length:
            return self

        else:
            # Can just blindly invert all bytes, as we don't care about what the
            # unused tail bits end up as.
            inverted_buf = bytes([~byte & 0xff for byte in self.__buf[:self.__length // 8 + 1]])
            return Bits.from_bytes(inverted_buf, self.__length)

    def startswith(self, prefix):
        """Return true if self starts with prefix"""
        if self.__class__ is not prefix.__class__:
            raise TypeError("Can't compute whether <%s>.startswith(<%s>)" % \
                            (self.__class__.__qualname__, prefix.__class__.__qualname__))

        if len(prefix) > len(self):
            return False

        elif len(prefix) == len(self):
            return prefix == self

        else:
            return self[:len(prefix)] == prefix

    def common_prefix(self, rhs):
        """Return the common prefix"""
        if self.__class__ is not rhs.__class__:
            raise TypeError("Can't compute the common prefix of %s and %s" % \
                            (self.__class__.__qualname__, rhs.__class__.__qualname__))

        # Arrange so shorter is the "left-hand-side" and longer is the "right-hand-side"
        lhs, rhs = (self, rhs) if self.__length <= rhs.__length else (rhs, self)

        common_prefix_length = (lhs.__length // 8)*8
        fwb_eq = False
        for i in range(lhs.__length // 8):
            if lhs.__buf[i] != rhs.__buf[i]:
                # Difference found in full-width bytes
                common_prefix_length = i * 8
                break

        else:
            # No full-width differences found.
            fwb_eq = True

        # Check remaining bits
        if common_prefix_length < lhs.__length:
            # XOR
            diff_bits = lhs.__buf[common_prefix_length // 8] ^ rhs.__buf[common_prefix_length // 8]

            # and shift left until either the common_prefix_length is the same
            # length as the lhs, or we find a difference
            while common_prefix_length < lhs.__length and not diff_bits & 0x80:
                diff_bits = (diff_bits << 1) & 0xFF
                common_prefix_length += 1

        assert common_prefix_length <= lhs.__length

        # If the common prefix is the same length as the lhs length, then we
        # can just return the lhs directly
        if common_prefix_length == lhs.__length:
            assert fwb_eq
            return lhs

        # Otherwise, return a new Bits using the lhs's buffer with the common
        # prefix length
        else:
            return Bits.from_bytes(lhs.__buf, common_prefix_length)




class BitsSerializer(proofmarshal.serialize.Serializer):
    @classmethod
    def check_instance(cls, instance):
        return instance.__class__ is Bits

    @classmethod
    def ctx_serialize(cls, value, ctx):
        """Serialize to a context"""
        ctx.write_varuint(value._Bits__length)
        ctx.write_bytes(value._Bits__full_width_prefix())
        if value._Bits__length % 8:
            ctx.write_bytes(bytes([value._Bits__tail_bits()]))

    @classmethod
    def ctx_deserialize(cls, ctx):
        """Deserialize from a context"""
        length = ctx.read_varuint()
        buf = ctx.read_bytes(length // 8 + (1 if length % 8 else 0))
        r = Bits.from_bytes(buf, length)
        # FIXME: should throw a serialization exception
        assert r._Bits__tail_bits() == buf[-1]
        return r


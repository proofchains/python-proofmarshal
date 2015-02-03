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

from proofmarshal.serialize import *

class Test_FixedBytes(unittest.TestCase):
    def test_init(self):
        with self.assertRaises(TypeError):
            FixedBytes('1')
        with self.assertRaises(ValueError):
            FixedBytes(-1)

    def test_check_instance(self):
        """FixedBytes.check_instance()"""

        with self.assertRaises(SerializerTypeError):
            FixedBytes(1).check_instance(None)
        with self.assertRaises(SerializerTypeError):
            FixedBytes(1).check_instance('')

        with self.assertRaises(SerializerValueError):
            FixedBytes(1).check_instance(b'')
        with self.assertRaises(SerializerValueError):
            FixedBytes(1).check_instance(b'12')

    def test_serialization(self):
        def T(expected_deserialized_value, expected_serialized):
            cls = FixedBytes(len(expected_deserialized_value))

            actual_serialized = cls.serialize(expected_deserialized_value)
            self.assertEqual(expected_serialized, actual_serialized)

            actual_deserialized_value = cls.deserialize(actual_serialized)
            self.assertEqual(expected_deserialized_value, actual_deserialized_value)

        T(b'', b'')
        T(b'a', b'a')
        T(b'ab', b'ab')
        T(b'abc', b'abc')

class FooSerializable(Serializable):
    HASH_HMAC_KEY = b'\x00'*16

    SERIALIZED_ATTRS = [('n', UInt8)]

class Test_Serializable(unittest.TestCase):
    def test_immutable(self):
        """Serializable instances are immutable"""
        f = FooSerializable(n=0)

        with self.assertRaises(TypeError):
            f.n = 10
        with self.assertRaises(TypeError):
            del f.n

    def test_serialization(self):
        f = FooSerializable(n=0)
        self.assertEqual(f.serialize(f), b'\x00')

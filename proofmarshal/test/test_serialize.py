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

from proofmarshal.serialize import *

class Test_SerBool(unittest.TestCase):
    def test_check_instance(self):
        """SerBool.check_instance()"""

        SerBool.check_instance(True)
        SerBool.check_instance(False)
        with self.assertRaises(SerializerTypeError):
            SerBool.check_instance(None)

    def test_serialization(self):
        """Serialization of bools"""
        self.assertEqual(SerBool.serialize(True),  b'\xff')
        self.assertEqual(SerBool.serialize(False), b'\x00')

    def test_deserialization(self):
        """Deserialization of bools"""
        self.assertIs(SerBool.deserialize(b'\xff'), True)
        self.assertIs(SerBool.deserialize(b'\x00'), False)

    def test_corrupted_deserialization(self):
        """Deserialization of corrupted bools"""
        with self.assertRaises(DeserializationError):
            SerBool.deserialize(b'\x01')
        with self.assertRaises(DeserializationError):
            SerBool.deserialize(b'\xfe')

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

class Test_VarBytes(unittest.TestCase):
    def test_init(self):
        with self.assertRaises(TypeError):
            VarBytes('1')
        with self.assertRaises(ValueError):
            VarBytes(-1)
        with self.assertRaises(ValueError):
            VarBytes(1,-1)
        with self.assertRaises(ValueError):
            VarBytes(1,0)
        with self.assertRaises(ValueError):
            VarBytes(1,1)

    def test_check_instance(self):
        """VarBytes.check_instance()"""

        with self.assertRaises(SerializerTypeError):
            VarBytes(1).check_instance(None)
        with self.assertRaises(SerializerTypeError):
            VarBytes(1).check_instance('')

        with self.assertRaises(SerializerValueError):
            VarBytes(1,2).check_instance(b'')
        with self.assertRaises(SerializerValueError):
            VarBytes(1,2).check_instance(b'123')

    def test_serialization(self):
        def T(expected_deserialized_value, expected_serialized):
            cls = VarBytes(max(len(expected_deserialized_value),1))

            actual_serialized = cls.serialize(expected_deserialized_value)
            self.assertEqual(expected_serialized, actual_serialized)

            actual_deserialized_value = cls.deserialize(actual_serialized)
            self.assertEqual(expected_deserialized_value, actual_deserialized_value)

        T(b'', b'\x00')
        T(b'a', b'\x01a')
        T(b'ab', b'\x02ab')
        T(b'abc', b'\x03abc')

    def test_deserialization(self):
        def T(serialized_value, expected_deserialized):
            cls = VarBytes(2**16)

            actual_deserialized = cls.deserialize(serialized_value)
            self.assertEqual(expected_deserialized, actual_deserialized)

        T(b'\x00', b'')
        T(b'\x01a', b'a')
        T(b'\x02ab', b'ab')
        T(b'\x03abc', b'abc')

    def test_invalid_deserialization(self):
        with self.assertRaises(DeserializationError):
            VarBytes(1).deserialize(b'\x02ab')
        with self.assertRaises(DeserializationError):
            VarBytes(2,3).deserialize(b'\x02a')
        with self.assertRaises(DeserializationError):
            VarBytes(2,3).deserialize(b'\x02')

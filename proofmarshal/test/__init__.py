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
import json
import os

def x(h):
    h = h.replace(' ','')
    return binascii.unhexlify(h.encode('utf8'))

def b2x(b):
    return binascii.hexlify(b).decode('utf8')

def load_test_vectors(name):
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        for test_case in json.load(fd):
            if len(test_case) != 1:
                yield test_case

            else:
                # line comment
                pass

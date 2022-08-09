#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# pwexplode.py - implementation of the PKWARE Data Compression Library
# format (imploding) for byte streams
# Copyright (C) 2019 by Sven Kochmann, Philippe Valembois

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the  Free Software Foundation,  either version 3  of the License, or
# (at your option) any later version.

# This program  is distributed  in the hope  that it will  be  useful,
# but  WITHOUT  ANY  WARRANTY;  without even  the implied warranty  of
# MERCHANTABILITY  or  FITNESS  FOR  A  PARTICULAR  PURPOSE.  See  the
# GNU General Public License for more details.

# You  should  have  received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

# Note: this program is mostly based on the description of Ben Rudiak-
# Gould in the comp.compression group:
# https://groups.google.com/forum/#!msg/comp.compression/M5P064or93o/W1ca1-ad6kgJ
# and zlib's blast.c:
# https://github.com/madler/zlib/blob/master/contrib/blast/blast.c#L150

# It should be noted that  there is  a small mistake in Ben's example.
# He uses  00 04 82 24 25 c7 80 7f as example, which should decompress
# to 'AIAIAIAIAIAIA'.  However,  testing  this with  my implementation
# failed.  When  I created it  with  the official pkware ziptool  (see
# below  for  tests),  the   sequence  turned  out   to  be   actually
# 00 04 82 24 25 8f 80 7f (notice the difference at byte 6). This will
# successfully decompress to 'AIAIAIAIAIAIA'.

# Import stuff
import collections.abc
from functools import wraps

try:
    range = xrange
except NameError:
    pass

# Debug flag; turning it on will make everything very noisy!
debugflag = False

# Quick & dirty debug printing function; prints only if debugflag is True; gets line number and everything from
# the currentframes _parent_ (f_back!)
def debug_print(text):
    if debugflag:
        import inspect
        cf = inspect.currentframe()
        print(f"pwexplode.{inspect.getframeinfo(cf.f_back)[2]}(), {cf.f_back.f_lineno}: {text}")

def tobytes(iterable):
    for b in iterable:
        yield ord(b)

def coroutine(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        cr = func(*args, **kwargs)
        next(cr)
        return cr
    return wrapper

class NoMoreDataException(Exception):
    pass

class ByteStream:
    def __init__(self):
        self.buffer = bytearray()
        self.pos = 0

    def push(self, data):
        self.buffer.extend(data)

    def pull(self, backbuffer=0):
        if backbuffer < 0:
            return

        result = self.buffer[self.pos:]

        nlen = len(self.buffer)
        if nlen > backbuffer:
            nlen = backbuffer

        if nlen == 0:
            self.buffer = bytearray()
        else:
            self.buffer = self.buffer[-nlen:]
        assert(len(self.buffer) == nlen)
        self.pos = nlen

        return result

    def copy(self, dist, size):
        offset = len(self.buffer) - dist - 1
        assert(offset >= 0)

        remain = size
        while remain > 0:
            end = offset + remain
            if end > len(self.buffer):
                end = len(self.buffer)
            self.buffer += self.buffer[offset:end]
            remain -= end - offset

        assert(remain == 0)
        #return self.buffer[offset:offset+size]

class BitStream:
    def __init__(self):
        self.buffer = ''
        self.pos = 0
        self.purgecnt = 0

    def is_finished(self):
        return (len(self.buffer) - self.pos) < 8 and all([x == '0' for x in self.buffer[self.pos:]])

    def push(self, data):
        buf = ''
        if type(data) is str:
            data = tobytes(data)
        for b in data:
            buf += f'{b:08b}'[::-1]
        self.buffer += buf

    def purge(self):
        self.buffer = self.buffer[self.pos:]
        self.pos = 0
        self.purgecnt += 1

    def save_state(self):
        return (self.purgecnt, self.pos)

    def restore_state(self, old_state):
        if old_state[0] != self.purgecnt:
            raise RuntimeError("A purge occured between saving and restoring state")

        self.pos = old_state[1]

    def read(self, size):
        buf = self.buffer
        pos = self.pos
        available_bits = len(buf) - pos

        if size > available_bits:
            raise NoMoreDataException()

        result = buf[pos:pos+size]
        self.pos += size
        return result

    def read_int(self, size):
        bits = self.read(size)
        return int(bits[::-1], 2)

# We implement look up tables as a Binary Search Tree
class Node:
    __slots__ = ['value', 'left', 'right']
    def __init__(self, value=None):
        self.value = value
        self.left = None
        self.right = None

    def ileft(self):
        assert(self.value is None)
        if self.left is not None:
            return self.left
        self.left = Node()
        return self.left

    def iright(self):
        assert(self.value is None)
        if self.right is not None:
            return self.right
        self.right = Node()
        return self.right

    def set_value(self, value):
        assert(self.left is None)
        assert(self.right is None)
        self.value = value

class BST:
    __slots__ = ['root']
    NOT_FOUND = object()

    def __init__(self, key_values):
        self.root = Node()
        if isinstance(key_values, collections.abc.Mapping):
            try:
                key_values = iter(key_values.items())
            except AttributeError:
                key_values = list(key_values.items())

        for k,v in key_values:
            self.insert(k, v)

    def insert(self, key, value):
        n = self.root
        for k in key:
            if k == '0':
                n = n.ileft()
            else:
                n = n.iright()
        n.set_value(value)

    def find(self, key):
        n = self.root
        for k in key:
            if k == '0':
                n = n.left
            else:
                n = n.right
            if n is None:
                return NOT_FOUND
        return n.value

    def sfind(self, keystream):
        n = self.root
        while n.value is None:
            k = keystream.read(1)[0]
            if k == '0':
                n = n.left
            else:
                n = n.right
            if n is None:
                return NOT_FOUND
        return n.value

literals = BST({"1111": 0x20, "11101": 0x45, "11100": 0x61, "11011": 0x65, "11010": 0x69, "11001": 0x6c, "11000": 0x6e,
                "10111": 0x6f, "10110": 0x72, "10101": 0x73, "10100": 0x74, "10011": 0x75, "100101": 0x2d,
                "100100": 0x31, "100011": 0x41, "100010": 0x43, "100001": 0x44, "100000": 0x49, "011111": 0x4c,
                "011110": 0x4e, "011101": 0x4f, "011100": 0x52, "011011": 0x53, "011010": 0x54, "011001": 0x62,
                "011000": 0x63, "010111": 0x64, "010110": 0x66, "010101": 0x67, "010100": 0x68, "010011": 0x6d,
                "010010": 0x70, "0100011": 0x0a, "0100010": 0x0d, "0100001": 0x28, "0100000": 0x29, "0011111": 0x2c,
                "0011110": 0x2e, "0011101": 0x30, "0011100": 0x32, "0011011": 0x33, "0011010": 0x34, "0011001": 0x35,
                "0011000": 0x37, "0010111": 0x38, "0010110": 0x3d, "0010101": 0x42, "0010100": 0x46, "0010011": 0x4d,
                "0010010": 0x50, "0010001": 0x55, "0010000": 0x6b, "0001111": 0x77, "00011101": 0x09, "00011100": 0x22,
                "00011011": 0x27, "00011010": 0x2a, "00011001": 0x2f, "00011000": 0x36, "00010111": 0x39,
                "00010110": 0x3a, "00010101": 0x47, "00010100": 0x48, "00010011": 0x57, "00010010": 0x5b,
                "00010001": 0x5f, "00010000": 0x76, "00001111": 0x78, "00001110": 0x79, "000011011": 0x2b,
                "000011010": 0x3e, "000011001": 0x4b, "000011000": 0x56, "000010111": 0x58, "000010110": 0x59,
                "000010101": 0x5d, "0000101001": 0x21, "0000101000": 0x24, "0000100111": 0x26, "0000100110": 0x71,
                "0000100101": 0x7a, "00001001001": 0x00, "00001001000": 0x3c, "00001000111": 0x3f, "00001000110": 0x4a,
                "00001000101": 0x51, "00001000100": 0x5a, "00001000011": 0x5c, "00001000010": 0x6a, "00001000001": 0x7b,
                "00001000000": 0x7c, "000001111111": 0x01, "000001111110": 0x02, "000001111101": 0x03,
                "000001111100": 0x04, "000001111011": 0x05, "000001111010": 0x06, "000001111001": 0x07,
                "000001111000": 0x08, "000001110111": 0x0b, "000001110110": 0x0c, "000001110101": 0x0e,
                "000001110100": 0x0f, "000001110011": 0x10, "000001110010": 0x11, "000001110001": 0x12,
                "000001110000": 0x13, "000001101111": 0x14, "000001101110": 0x15, "000001101101": 0x16,
                "000001101100": 0x17, "000001101011": 0x18, "000001101010": 0x19, "000001101001": 0x1b,
                "000001101000": 0x1c, "000001100111": 0x1d, "000001100110": 0x1e, "000001100101": 0x1f,
                "000001100100": 0x23, "000001100011": 0x25, "000001100010": 0x3b, "000001100001": 0x40,
                "000001100000": 0x5e, "000001011111": 0x60, "000001011110": 0x7d, "000001011101": 0x7e,
                "000001011100": 0x7f, "000001011011": 0xb0, "000001011010": 0xb1, "000001011001": 0xb2,
                "000001011000": 0xb3, "000001010111": 0xb4, "000001010110": 0xb5, "000001010101": 0xb6,
                "000001010100": 0xb7, "000001010011": 0xb8, "000001010010": 0xb9, "000001010001": 0xba,
                "000001010000": 0xbb, "000001001111": 0xbc, "000001001110": 0xbd, "000001001101": 0xbe,
                "000001001100": 0xbf, "000001001011": 0xc0, "000001001010": 0xc1, "000001001001": 0xc2,
                "000001001000": 0xc3, "000001000111": 0xc4, "000001000110": 0xc5, "000001000101": 0xc6,
                "000001000100": 0xc7, "000001000011": 0xc8, "000001000010": 0xc9, "000001000001": 0xca,
                "000001000000": 0xcb, "000000111111": 0xcc, "000000111110": 0xcd, "000000111101": 0xce,
                "000000111100": 0xcf, "000000111011": 0xd0, "000000111010": 0xd1, "000000111001": 0xd2,
                "000000111000": 0xd3, "000000110111": 0xd4, "000000110110": 0xd5, "000000110101": 0xd6,
                "000000110100": 0xd7, "000000110011": 0xd8, "000000110010": 0xd9, "000000110001": 0xda,
                "000000110000": 0xdb, "000000101111": 0xdc, "000000101110": 0xdd, "000000101101": 0xde,
                "000000101100": 0xdf, "000000101011": 0xe1, "000000101010": 0xe5, "000000101001": 0xe9,
                "000000101000": 0xee, "000000100111": 0xf2, "000000100110": 0xf3, "000000100101": 0xf4,
                "0000001001001": 0x1a, "0000001001000": 0x80, "0000001000111": 0x81, "0000001000110": 0x82,
                "0000001000101": 0x83, "0000001000100": 0x84, "0000001000011": 0x85, "0000001000010": 0x86,
                "0000001000001": 0x87, "0000001000000": 0x88, "0000000111111": 0x89, "0000000111110": 0x8a,
                "0000000111101": 0x8b, "0000000111100": 0x8c, "0000000111011": 0x8d, "0000000111010": 0x8e,
                "0000000111001": 0x8f, "0000000111000": 0x90, "0000000110111": 0x91, "0000000110110": 0x92,
                "0000000110101": 0x93, "0000000110100": 0x94, "0000000110011": 0x95, "0000000110010": 0x96,
                "0000000110001": 0x97, "0000000110000": 0x98, "0000000101111": 0x99, "0000000101110": 0x9a,
                "0000000101101": 0x9b, "0000000101100": 0x9c, "0000000101011": 0x9d, "0000000101010": 0x9e,
                "0000000101001": 0x9f, "0000000101000": 0xa0, "0000000100111": 0xa1, "0000000100110": 0xa2,
                "0000000100101": 0xa3, "0000000100100": 0xa4, "0000000100011": 0xa5, "0000000100010": 0xa6,
                "0000000100001": 0xa7, "0000000100000": 0xa8, "0000000011111": 0xa9, "0000000011110": 0xaa,
                "0000000011101": 0xab, "0000000011100": 0xac, "0000000011011": 0xad, "0000000011010": 0xae,
                "0000000011001": 0xaf, "0000000011000": 0xe0, "0000000010111": 0xe2, "0000000010110": 0xe3,
                "0000000010101": 0xe4, "0000000010100": 0xe6, "0000000010011": 0xe7, "0000000010010": 0xe8,
                "0000000010001": 0xea, "0000000010000": 0xeb, "0000000001111": 0xec, "0000000001110": 0xed,
                "0000000001101": 0xef, "0000000001100": 0xf0, "0000000001011": 0xf1, "0000000001010": 0xf5,
                "0000000001001": 0xf6, "0000000001000": 0xf7, "0000000000111": 0xf8, "0000000000110": 0xf9,
                "0000000000101": 0xfa, "0000000000100": 0xfb, "0000000000011": 0xfc, "0000000000010": 0xfd,
                "0000000000001": 0xfe, "0000000000000": 0xff })

lengths = BST({'00000010111000': 150, '00000010111001': 214, '000000011010110': 371, '000000011010111': 499,
               '00000011101000': 147, '00000011101001': 211, '000000010011011': 481, '000001101001': 109,
               '000001101000': 77, '000000011011100': 323, '000000011011101': 451, '011': 5, '000000000100110': 364,
               '00000011111001': 215, '00010100': 17, '00010101': 21, '000000001101110': 382, '000000001101111': 510,
               '000000001110110': 374, '00000010100111': 250, '000001001110': 100, '000001001111': 132,
               '000000001000101': 426, '000000001000100': 298, '000000001100100': 302, '000000001100101': 430,
               '000000010101110': 381, '000000010101111': 509, '000000000110100': 308, '000000000110101': 436,
               '000001110010': 91, '000001110011': 123, '000000010100100': 301, '000000010100101': 429,
               '0000110101': 34, '0000110100': 26, '00000010011100': 164, '00000010011101': 228, '000000000010101': 432,
               '000000010001111': 505, '00000011000111': 249, '00000010010110': 188, '00000010010111': 252,
               '000000011111000': 295, '000000011111001': 423, '00000010100011': 234, '00000010100010': 170,
               '000000000000011': 456, '000000010000110': 361, '000000010000111': 489, '00000010101010': 178,
               '00000010101011': 242, '000000001111010': 358, '000000001111011': 486, '00000011111010': 183,
               '00000011111011': 247, '00010010': 18, '00000010110001': 206, '00000010110000': 142,
               '00000011111110': 199, '00000010000100': 152, '00000010000101': 216, '000000000100011': 460,
               '000000000100010': 332, '000001011111': 134, '000001011110': 102, '000000011101010': 351,
               '000000011111010': 359, '00000011111111': 263, '00000010001110': 192, '00000010001111': 256,
               '000001010101': 114, '000001010100': 82, '000001110100': 83, '000001110101': 115, '000000010100010': 333,
               '000000010100011': 461, '00000011100001': 203, '00000011100000': 139, '000000011100101': 431,
               '000001111110': 103, '000001111111': 135, '000000001011111': 514, '000000000000100': 296,
               '000000000000101': 424, '000000011001110': 379, '000000011001111': 507, '00000011110000': 143,
               '00000011110001': 207, '001001': 11, '001000': 10, '000000010001001': 409, '000000010010010': 337,
               '000000010010011': 465, '000000011000100': 299, '000000011000101': 427, '000000000101001': 412,
               '000000000101000': 284, '00001000110': 52, '00001000111': 68, '00000011001100': 161,
               '00000011001101': 225, '000000010110011': 469, '000000010011010': 353, '000000010111001': 421,
               '000001111101': 119, '000000000101100': 316, '00000011000110': 185, '0000110001': 32,
               '00000011011111': 261, '000000000101101': 444, '0000111111': 39, '0000111110': 31,
               '000000010111000': 293, '00001011101': 63, '00001011100': 47, '000000001011110': 386,
               '000000011100100': 303, '000001010011': 122, '000001010010': 90, '000000010101000': 285,
               '000000010110010': 341, '000001011010': 94, '000001011011': 126, '000000001010100': 306,
               '000000011101110': 383, '00000011010111': 253, '00000011010110': 189, '00001010111': 69,
               '00001010110': 53, '000001101111': 133, '000001101110': 101, '100': 4, '101': 2, '00000011011101': 229,
               '00000011011100': 165, '000000000100111': 492, '000001100101': 113, '000001100100': 81,
               '00000011000000': 137, '00001001101': 62, '000000010111100': 325, '000001001000': 76,
               '000001001001': 108, '000000001100010': 334, '000000010001110': 377, '000000011011010': 355,
               '000000000110010': 340, '000000001001110': 378, '000000011011011': 483, '000000001011100': 322,
               '0001110': 13, '0001111': 15, '000000000011001': 416, '000000000011000': 288, '0000110011': 36,
               '0000110010': 28, '000000011111101': 455, '00000011011001': 213, '000000010110000': 277,
               '000000011111100': 327, '000000001101011': 478, '000000001101010': 350, '000000000111011': 484,
               '000000000111010': 356, '00000011111100': 167, '00000011111101': 231, '000000011001011': 475,
               '00000010110111': 254, '00000010110110': 190, '000000011010011': 467, '000000011010010': 339,
               '00000010001000': 144, '00000010001001': 208, '000000001001001': 410, '000000001001000': 282,
               '000000011110100': 311, '00000010011001': 212, '00000010101100': 162, '00000010101101': 226,
               '000000001001111': 506, '000001111000': 79, '000001111001': 111, '000001000001': 104, '000001000000': 72,
               '000000010000011': 457, '000000010000010': 329, '000000000011101': 448, '000000001110111': 502,
               '00000011101101': 227, '00000011101100': 163, '00000010011000': 148, '000000011000010': 331,
               '000000011000011': 459, '00000011010001': 205, '00000011010000': 141, '000000010011101': 449,
               '000000010011100': 321, '000000001010010': 338, '00001001100': 46, '00101': 9, '000000010010111': 497,
               '000000010010110': 369, '000000010100111': 493, '000000010100110': 365, '000000000001011': 472,
               '000000000001010': 344, '000000000011111': 512, '00001010001': 57, '00001010000': 41,
               '000000000000010': 328, '000000011001010': 347, '00010001': 20, '00010000': 16, '000000010001000': 281,
               '000000010001100': 313, '000000001011011': 482, '000000001011010': 354, '000001100011': 121,
               '000001100010': 89, '000000001000000': 266, '000000001000001': 394, '00001000011': 64, '00001000010': 48,
               '0000111010': 29, '0000111011': 37, '00000010010000': 140, '00000010010001': 204, '000000010101001': 413,
               '000000000010110': 368, '000000010001101': 441, '000000000010111': 496, '000001010110': 98,
               '000001010111': 130, '000000011010101': 435, '000000011010100': 307, '000000000001101': 440,
               '000000001100011': 462, '000000000001100': 312, '00000011100111': 251, '000000011011110': 387,
               '000001101010': 93, '000001101011': 125, '000000011111011': 487, '00000011011011': 245,
               '000000010110110': 373, '000000010110111': 501, '00000011011010': 181, '000000000110011': 468,
               '00000010000001': 200, '00000010000000': 136, '000000001101101': 446, '000000001101100': 318,
               '000000000111101': 452, '000000000111100': 324, '000000001010011': 466, '000000001100111': 494,
               '000000001100110': 366, '000000010101101': 445, '000000010101100': 317, '000000001110011': 470,
               '000000000110110': 372, '00000010111101': 230, '00000010111100': 166, '0000110110': 30, '0000110111': 38,
               '000000011100111': 495, '000000011110010': 343, '000000011110011': 471, '00000011110101': 223,
               '00000011110100': 159, '000000010001011': 473, '00000010100000': 138, '00000010100001': 202,
               '00001011000': 43, '00001011001': 59, '000000000110111': 500, '000000010000101': 425,
               '000000010000100': 297, '000001000111': 128, '000001000110': 96, '00000011001001': 209,
               '00000011001000': 145, '00000010110010': 174, '00000010110011': 238, '000000000010000': 272,
               '000000000010001': 400, '000000011100011': 463, '000000010111011': 485, '000000011101001': 415,
               '000000011101000': 287, '000001011100': 86, '000001011101': 118, '00001001010': 50, '00001001011': 66,
               '000000000010100': 304, '00000011101011': 243, '00000011101010': 179, '000000010100001': 397,
               '000000010100000': 269, '00000011100010': 171, '00000011100011': 235, '000000011100010': 335,
               '000000001110101': 438, '000000000000111': 488, '000000000000110': 360, '000000011001101': 443,
               '000000011001100': 315, '00000011000011': 233, '00010111': 23, '00010110': 19, '000000010010001': 401,
               '000000010010000': 273, '000000011000111': 491, '000000011000110': 363, '000001001101': 116,
               '00001000100': 44, '000000001000110': 362, '000000001000111': 490, '000000001110100': 310,
               '000001110001': 107, '000001110000': 75, '00001000101': 60, '0000111100': 27, '0000111101': 35,
               '00000010011111': 260, '00000010011110': 196, '000001001100': 84, '000001010000': 74,
               '000001010001': 106, '000000010110001': 405, '00000010010101': 220, '00000010010100': 156,
               '000000001010111': 498, '000000001010110': 370, '000000011101111': 511, '00000011010100': 157,
               '000001101101': 117, '000000011011001': 419, '000000011011000': 291, '00000010101001': 210,
               '00000010101000': 146, '000001100110': 97, '00000011111000': 151, '000000000111110': 388,
               '000000010111010': 357, '00000010000111': 248, '00000010000110': 184, '000000000100000': 268,
               '000000000100001': 396, '000000011101011': 479, '000000000000001': 392, '00000010001101': 224,
               '00000010001100': 160, '000000001100001': 398, '000000001100000': 270, '000000011100000': 271,
               '000000000000000': 264, '000000000110001': 404, '000000000110000': 276, '00000010111011': 246,
               '00000010111010': 182, '0001101': 14, '0001100': 12, '0000110000': 24, '000001111100': 87, '0101': 6,
               '0100': 7, '000000000111111': 516, '00000011110011': 239, '00000011110010': 175, '000000011000001': 395,
               '000000011011111': 515, '000000000101010': 348, '000000000101011': 476, '00000011001111': 257,
               '00000011001110': 193, '000000010011000': 289, '000000010011001': 417, '00000010110100': 158,
               '00000010110101': 222, '00000011000101': 217, '00000011000100': 153, '000000000100101': 428,
               '000000000100100': 300, '000000011100110': 367, '000000000011100': 320, '000000011110111': 503,
               '000000011110110': 375, '00001011110': 55, '00001011111': 71, '000000010001010': 345, '00001010100': 45,
               '00001010101': 61, '000000011101100': 319, '000000011101101': 447, '000001011001': 110,
               '000001011000': 78, '00000011100100': 155, '00000011100101': 219, '000000000001110': 376,
               '000000001111111': 518, '000000001011101': 450, '000001000010': 88, '000001000011': 120,
               '000000011010000': 275, '000000011010001': 403, '00000011101110': 195, '00000011101111': 259,
               '000000001011000': 290, '000001001011': 124, '000001001010': 92, '00000011010010': 173,
               '00000011010011': 237, '000000000001111': 504, '000000001111110': 390, '000000001001100': 314,
               '000000001001101': 442, '000001110111': 131, '000001110110': 99, '00001001111': 70, '00001001110': 54,
               '000000001110010': 342, '000000000011010': 352, '000000000101110': 380, '000000001110000': 278,
               '000000001110001': 406, '000000010101011': 477, '000000001010001': 402, '000000001010000': 274,
               '000000010101010': 349, '000000001101000': 286, '000000001101001': 414, '11': 3, '000000000111000': 292,
               '000000000111001': 420, '00000011011000': 149, '00010011': 22, '000000001000011': 458,
               '000000001000010': 330, '000001100000': 73, '000001100001': 105, '000000001011001': 418,
               '000000001111001': 422, '000000011000000': 267, '000000011110101': 439, '000001101100': 85,
               '00000010001011': 240, '00000010001010': 176, '00000011010101': 221, '00000010101111': 258,
               '00000010101110': 194, '00001001001': 58, '00001001000': 42, '0011': 8, '000000010111101': 453,
               '000000011111110': 391, '00000010100101': 218, '00000010100100': 154, '000000001111000': 294,
               '000001111011': 127, '000001111010': 95, '000000010000000': 265, '000000010000001': 393,
               '000000001111100': 326, '000000001111101': 454, '000000010110101': 437, '000000010110100': 309,
               '000000011111111': 519, '000000011100001': 399, '00000010000010': 168, '00000010000011': 232,
               '000000000011011': 480, '000000010011110': 385, '000000010011111': 513, '00000011000001': 201,
               '00000010111110': 198, '00000011000010': 169, '000000010010100': 305, '000000010010101': 433,
               '00000011011110': 197, '000000000001000': 280, '000000000001001': 408, '000001100111': 129,
               '000000011110001': 407, '000000011110000': 279, '000000001010101': 434, '00001010010': 49,
               '00001010011': 65, '000000011001000': 283, '000000011001001': 411, '00000011110110': 191,
               '00000011110111': 255, '00001011011': 67, '00001011010': 51, '000001000100': 80, '000001000101': 112,
               '000000000101111': 508, '00000010100110': 186, '00001000000': 40, '00001000001': 56,
               '00000011001010': 177, '00000011001011': 241, '00000011100110': 187, '000000010111111': 517,
               '000000010111110': 389, '000000000011110': 384, '00000010111111': 262, '000000000010011': 464,
               '000000000010010': 336, '00000010010011': 236, '00000010010010': 172, '0000111001': 33, '0000111000': 25,
               '00000010011010': 180, '00000010011011': 244, '000000001001010': 346, '000000001001011': 474})

offsets = BST({"11": 0x00, "1011": 0x01, "1010": 0x02, "10011": 0x03, "10010": 0x04, "10001": 0x05, "10000": 0x06,
              "011111": 0x07, "011110": 0x08, "011101": 0x09, "011100": 0x0a, "011011": 0x0b, "011010": 0x0c,
              "011001": 0x0d, "011000": 0x0e, "010111": 0x0f, "010110": 0x10, "010101": 0x11, "010100": 0x12,
              "010011": 0x13, "010010": 0x14, "010001": 0x15, "0100001": 0x16, "0100000": 0x17, "0011111": 0x18,
              "0011110": 0x19, "0011101": 0x1a, "0011100": 0x1b, "0011011": 0x1c, "0011010": 0x1d, "0011001": 0x1e,
              "0011000": 0x1f, "0010111": 0x20, "0010110": 0x21, "0010101": 0x22, "0010100": 0x23, "0010011": 0x24,
              "0010010": 0x25, "0010001": 0x26, "0010000": 0x27, "0001111": 0x28, "0001110": 0x29, "0001101": 0x2a,
              "0001100": 0x2b, "0001011": 0x2c, "0001010": 0x2d, "0001001": 0x2e, "0001000": 0x2f, "00001111": 0x30,
              "00001110": 0x31, "00001101": 0x32, "00001100": 0x33, "00001011": 0x34, "00001010": 0x35,
              "00001001": 0x36, "00001000": 0x37, "00000111": 0x38, "00000110": 0x39, "00000101": 0x3a,
              "00000100": 0x3b, "00000011": 0x3c, "00000010": 0x3d, "00000001": 0x3e, "00000000": 0x3f})

# This coroutine takes a compressed bytestring and decompresses it; returns the uncompressed data if successful
@coroutine
def explode():
    obuf = ByteStream()
    ibuf = BitStream()

    started = False
    codedliterals, maxdictlength = None, None
    dict_size = 0

    while True:
        ibuf.purge()
        odata = obuf.pull(dict_size)
        idata = (yield odata)

        # compressedstring should be a string...
        if type(idata) is not bytes:
            raise RuntimeError(f"explode(): data sent is not a str but {type(ibuf)}.")

        ibuf.push(idata)
        idata = None

        try:
            while True:
                ibuf_state = ibuf.save_state()
                if not started:
                    # Header is two bytes
                    codedliterals = ibuf.read_int(8)
                    maxdictlength = ibuf.read_int(8)
                    # First byte is 0 if literals are uncoded, otherwise 1
                    # Second byte is 4, 5, or 6 (max size of dictionary)
                    dict_size = 1 << (6+maxdictlength)
                    # Print
                    #debug_print(f"Literals are {'coded' if codedliterals == 1 else 'non-coded'}. Size of dictionary is {dict_size} ({maxdictlength}).")

                    # Test for dictionary size
                    if maxdictlength not in [4, 5, 6]:
                        raise RuntimeError(f"explode(compressedstring): only dictionary sizes of 4, 5, or 6 are supported. {maxdictlength} given.")

                    # Start decompression
                    #debug_print("Starting decompression...")
                    started = True

                    # Redo a loop
                    continue

                # Read one bit, it will tell if the next thing is a literal or a copy instruction
                bit = ibuf.read(1)[0]

                # Print
                #debug_print(f"bit ({bit}) says next is a {'literal' if not bit else 'copy instruction'}")

                # First bit = 0, means literal!
                if bit == '0':
                    # Are the literals coded?
                    if codedliterals == 1:
                        pchar = literals.sfind(ibuf)
                        if pchar is BST.NOT_FOUND:
                            raise RuntimeError("explode(): Tried to read in coded literal, but did not find anything. "
                                               "Maybe string isn't compressed?")

                        # Print
                        #debug_print(f"Found coded literal '\\x{pchar:02x}' from sequence '{''.join('1' if k else '0' for k in seq)}' ({len(seq)})")

                    # noncoded literal
                    else:
                        # Just take the next 8 bits and print it
                        pchar = ibuf.read_int(8)

                        # Print
                        #debug_print(f"Found non-coded literal '\\x{pchar:02x}' by reading in 8 bits")

                    # Add to output data
                    obuf.push((pchar, ))

                # Copy instructions!
                else:
                    # Length = number of bytes to copy
                    length = lengths.sfind(ibuf)
                    if length is BST.NOT_FOUND:
                        raise RuntimeError("explode(): Tried to read in length for copy instruction, but did not find "
                                           "anything. Maybe string isn't compressed?")

                    # End of stream?
                    if length == 519:
                        #debug_print(f"Found end of compressed bit sequence '{seq}' ({length}).")
                        break

                    # Print
                    #debug_print(f"{length} bytes need to be copied/filled.")

                    # Distance/offset from the _end_ of the dictionary (in decompresseddata) to copy
                    dist = offsets.sfind(ibuf)
                    if dist is BST.NOT_FOUND:
                        raise RuntimeError("explode(): Tried to read in distance/offset for copy instruction, "
                                           "but did not find anything. Maybe string isn't compressed?")

                    # Save for debug
                    raw_dist = dist

                    # Remaining bits (depending on length and maxdictlength)
                    bitsleft = (2 if length == 2 else maxdictlength)

                    # Shift a little bit
                    dist <<= bitsleft

                    # Save for debug
                    shifted_dist = dist

                    # Read remaining bits and add them to the distance.
                    short_dist = ibuf.read_int(bitsleft)
                    dist += short_dist

                    # Print
                    #debug_print(f"The final distance is {dist} (raw: {raw_dist}, shifted by {bitsleft}: {shifted_dist}, added: {short_dist})")

                    # Copy exactly 'length' number of bytes!
                    #debug_string =
                    obuf.copy(dist, length)

                    # Print
                    #debug_print(f"Copying and filling in {length} bytes from {dist}: {debug_string}")
        except NoMoreDataException:
            # We will feed at next step
            ibuf.restore_state(ibuf_state)
            continue
        else:
            # We broke the loop: we must have finished
            break
    # Send back last data
    ibuf.purge()
    assert(ibuf.is_finished())
    odata = obuf.pull(0)
    yield odata


# Someone calling this file directly? Then let's print some tests!
if __name__ == '__main__':
    import sys
    # Only for this use we define this test function
    def runtest(inputdata, outputdata, positivecounter, number):
        exploder = explode()
        # Decompress it!
        decompressed = exploder.send(inputdata)
        result = decompressed == outputdata

        # Print results for user
        print(f"Test {number + 1:02d}: '{inputdata}' should decompress to '{expectedoutput}'. Result = {bool(result)}")

        # Counting successful tests
        if result:
            positivecounter += 1
        else:
            print("Output gave: ", outputdata)
            sys.exit(1)

        return positivecounter, number + 1


    # Start test program
    print("pwexplode.py - implementation of the PKWARE Data Compression Library format (imploding) for byte streams")
    print("Copyright (C) 2021 by Sven Kochmann")
    print("")
    print("This program comes with ABSOLUTELY NO WARRANTY; This is free software, and you are welcome to redistribute")
    print("it under certain conditions; please see source code for details.")
    print("")
    print("Contributors: KOLANICH")
    print("")

    print("Running tests:")
    success, counter = 0, 0

    # All the tests
    success, counter = runtest(b'\x00\x04\x82\x24\x25\x8F\x80\x7F', b'AIAIAIAIAIAIA', success, counter)
    success, counter = runtest(b'\x01\x04\x62\x41\xF2\x08\xF8\x07', b'AIAIAIAIAIAIA', success, counter)
    success, counter = runtest(b'\x01\x04\x02\x6F\x5A\x08\xB6\x67\xE8\x86\x6A\xA9\x8A\x6D\x28'
                               b'\x5E\x56\x6D\xCD\x5B\x5B\x6C\x47\x73\x18\xB6\x8A\x17\xF0\x0F',
                               b'I like consistent user interfaces.', success, counter)
    success, counter = runtest(b'\x01\x06\x50\x6C\xD3\xD4\x3D\xBC\xAE\x99\x74\x50\x7A\x28\x3A'
                               b'\xBC\x77\x34\xDB\x83\xD3\x65\x7C\xAF\xE8\x74\x07\x1C\x88\x7B'
                               b'\x16\xC5\x52\xFD\x17\x1C\x0F\xC1\xD6\xC0\xF9\xB5\x31\xA8\x1B'
                               b'\xB4\xC1\x2B\x78\x01\xFF',
                               b'Hello world! How are you, today? This is a very long text.', success, counter)

    # Print results
    print(f"{success}/{counter} tests performed successfully.")

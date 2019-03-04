#!/usr/bin/env python

#    idecomp.py - Extractor of InstallShield 3.0 files
#    Copyright (C) 2018, 2019 by Philippe Valembois
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

# coding: utf-8
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

from __future__ import print_function

import argparse
import collections
import datetime
import fnmatch
import os
import struct
import sys
import time

import pwexplode

DEBUG = True

def filterfileobj(fsrc, fdst, in_length, filter=None, buffer_length=16*1024):
    """copy data from file-like object fsrc to file-like object fdst"""
    written = 0
    while in_length > 0:
        rd_length = in_length if in_length < buffer_length else buffer_length
        
        buf = fsrc.read(rd_length)
        if len(buf) < rd_length:
            raise Exception("File is shorter than expected")
        in_length -= rd_length

        if filter is not None:
            buf = filter.send(buf)

        fdst.write(buf)
        written += len(buf)
    return written

class ArchiveHeader(collections.namedtuple('ArchiveHeader', ['to1', 'to2', 'pad', 'has_password', 'flags',
    'num_files', 'file_date', 'original_archive_size', 'total_original_size', 'taken',
    'total_parts' ,'part_id', 'check_byte', 'end_integral_data', 'start_integral_data',
    'dirs_list_offset', 'dirs_list_size', 'num_dirs',
    'files_list_offset', 'files_list_size', 'password'])):
    # Flags : 0x1 : split file
    #         0x2 : split file contiguously (a file is not split across archive parts)
    # Taken is size of metadatas and incomplete file part
    # Check byte is total_compacted_size % 253
    @property
    def datetime(self):
        date = self.file_date & 0xffff
        time = (self.file_date >> 16) & 0xffff
        return datetime.datetime(((date >> 9) & 0x7f) + 1980,
                (date >> 5) & 0xf, date & 0x1f,
                (time >> 11) & 0x1f, (time >> 5) & 0x3f, (time & 0x1f) * 2)

class DirEntry(collections.namedtuple("DirEntry", ['num_files', 'entry_size', 'name_size', 'name', 'unused'])):
    @property
    def path(self):
        return self.name.replace('\\', '/')

class FileEntry(collections.namedtuple("FileEntry", ['end_part_id', 'dir_id', 'original_size', 'compacted_size',
    'data_offset', 'file_date', 'attribs', 'entry_size', 'flags', 'pad',
    'start_part_id', 'name_size', 'name', 'versionMS', 'versionLS', 'unused'])):
    # Flags: 0x100 = span on multiple files
    #        0x 40 = has version (not always set because filtered in icomp)
    #        0x 20 = invalid (used internally by icomp when removing files and shouldn't be observed in files)
    #        0x 10 = stored, not compressed

    def __new__(_cls, *args, **kwargs):
        dirs = kwargs.pop('dirs', None)
        archive = kwargs.pop('archive', None)
        inst = super(FileEntry, _cls).__new__(_cls, *args, **kwargs)
        if dirs is not None:
            inst.dir = dirs[inst.dir_id]
        else:
            inst.dir = None
        inst.archive = archive
        return inst

    @property
    def datetime(self):
        file_date = self.file_date & 0xffff
        file_time = (self.file_date >> 16) & 0xffff
        return datetime.datetime(((file_date >> 9) & 0x7f) + 1980,
                (file_date >> 5) & 0xf, file_date & 0x1f,
                (file_time >> 11) & 0x1f, (file_time >> 5) & 0x3f,
                (file_time & 0x1f) * 2)

    @property
    def timestamp(self):
        file_date = self.file_date & 0xffff
        file_time = (self.file_date >> 16) & 0xffff
        return time.mktime((
            ((file_date >> 9) & 0x7f) + 1980,
            (file_date >> 5) & 0xf, file_date & 0x1f,
            (file_time >> 11) & 0x1f, (file_time >> 5) & 0x3f,
            (file_time & 0x1f) * 2,
            -1, -1, -1))

    @property
    def attributes(self):
        ro = self.attribs & 0x1
        hidden = self.attribs & 0x2
        system = self.attribs & 0x4
        archive = self.attribs & 0x20
        return "{0}{1}{2}{3}".format(
                "A" if archive else "_",
                "H" if hidden else "_",
                "R" if ro else "_",
                "S" if system else "_")

    @property
    def path(self):
        return os.path.join(self.dir.path, self.name)

    def is_in_part(self, archive=None):
        if archive is None:
            archive = self.archive
        archiveHdr = archive.header
        if archiveHdr.flags & 0x3 == 0:
            # Not a split archive
            return True

        return (archiveHdr.part_id >= self.start_part_id and
                archiveHdr.part_id <= self.end_part_id)

    @property
    def is_correct(self):
        # Checks if the offsets, start and end parts id are correct
        # They are correct when file entry is loaded from :
        # - an unsplit archive
        # - the first part
        # - parts after the last part containing the data
        return self.archive.header.part_id <= 1 or self.archive.header.part_id >= self.end_part_id
    
    @property
    def split(self):
        return (self.flags & 0x100) != 0

    def __str__(self):
        if DEBUG:
            return u' {0:%m-%d-%y %H:%M} {1:>8} {2} {3:>8} {4}'.format(self.datetime, self.original_size, self.attributes, self.compacted_size, self.path.replace(os.sep, '\\'))
        else:
            return u' {0:%y-%m-%d %H:%M} {1:>8} {2} {3:>8} {4}'.format(self.datetime, self.original_size, self.attributes, self.compacted_size, self.path)

    def extract(self, base_path):
        if not self.is_correct:
            raise Exception("File entry is not valid for extraction")

        path = os.path.join(base_path, self.path)
        dir_path = os.path.dirname(path)
        try: 
            os.makedirs(dir_path)
        except OSError:
            if not os.path.isdir(dir_path):
                raise

        filter_coro = None
        if self.flags & 0x10 == 0:
            filter_coro = pwexplode.explode()

        of = open(path, 'wb')

        read_size = 0
        written_size = 0
        #print(repr(self))
        #print("Parts: {0}...{1}".format(self.start_part_id, self.end_part_id))
        for part_id in range(self.start_part_id, self.end_part_id + 1):
            archive = self.archive.get_part(part_id)
            #print("Opening part {0}: file {1}".format(part_id, archive.path))
            hdr = archive.header
            f = archive.file

            if part_id == self.start_part_id:
                start = self.data_offset
            else:
                start = 255

            if not self.split:
                # Not split: length is the whole file
                part_length = self.compacted_size
            elif part_id == self.end_part_id:
                # Last part: stop at first integral file
                part_length = hdr.start_integral_data - start
            else:
                part_length = hdr.dirs_list_offset - start

            f.seek(start)
            written_size += filterfileobj(f, of, part_length, filter=filter_coro)
            read_size += part_length

        assert(read_size == self.compacted_size)
        assert(written_size == self.original_size)

        of.close()
        os.utime(path, (time.time(), self.timestamp))
        # We can only keep RO attribute in a portable way
        ro = self.attribs & 0x1
        if ro:
            mode = os.stat(path).st_mode
            mode &= 0x7333
            os.chmod(filename, mode)

class Archive:
    def __init__(self, fName, encoding=None):
        self.path = fName
        if encoding is None:
            encoding = 'ascii'
        self.encoding = encoding

        self.dir_name, self.file_name = os.path.split(fName)
        self.base_name, _ = os.path.splitext(self.file_name)
        self.file = open(self.path, 'rb')

        self.magic = False
        self.header = None
        self.dirs = None
        self.files = None

        self.check_sig()
        self.load_hdr()
        self.load_dirs()
        self.load_files()

    def get_part(self, part_id):
        if self.header.flags & 0x3 == 0:
            # Not a split archive
            return self
        if self.header.part_id == part_id:
            return self

        other_part_name = os.path.join(self.dir_name, '{0}.{1}'.format(self.base_name, part_id))
        return Archive(other_part_name, self.encoding)

    def check_sig(self):
        f = self.file
        f.seek(0)
        magic = f.read(4)
        magic = struct.unpack("<L", magic)[0]
        if magic != 0x8C655D13:
            raise Exception("Invalid magic: {0:08x}".format(magic))

        self.magic = True

    def load_hdr(self):
        if not self.magic:
            self.check_sig()

        f = self.file
        f.seek(4)
        hdrSize = f.read(1)
        hdrSize = struct.unpack("<B", hdrSize)[0]
        if hdrSize != 0x3A:
            raise Exception("Invalid header size : {0:02x} != 0x3A".format(hdrSize))

        hdr = f.read(0x3A)
        assert(len(hdr) == struct.calcsize("<BBHBHHLLLLBBBLLLLHLLL"))
        hdr = struct.unpack("<BBHBHHLLLLBBBLLLLHLLL", hdr)
        hdr = ArchiveHeader(*hdr)

        self.header = hdr

    def load_dirs(self):
        if self.header is None:
            self.load_hdr()

        f = self.file
        f.seek(self.header.dirs_list_offset)
        dirs = list()
        pos = 0
        for i in range(self.header.num_dirs):
            dirHdr = f.read(6)
            dirHdr = struct.unpack("<HHH", dirHdr)
            ln = dirHdr[2]
            name = f.read(ln+1)
            name = name.decode(self.encoding)
            if name[-1:] != '\x00':
                print(u"Invalid dir name last character: {0!r} for {1}".format(name[-1], name[:-1]), file=sys.stderr)
            name = name[:-1]
            assert(len(name) == ln)
            dirFtr = f.read(4)
            dirFtr = struct.unpack("<L", dirFtr)
            dirEntry = DirEntry(*(dirHdr + (name, ) + dirFtr))
            dirs.append(dirEntry)
            assert(dirEntry.entry_size == 11 + dirEntry.name_size)
            pos += dirEntry.entry_size
        assert(pos == self.header.dirs_list_size)
        self.dirs = dirs

    def load_files(self):
        if self.dirs is None:
            self.load_dirs()

        f = self.file
        f.seek(self.header.files_list_offset)

        files = list()
        pos = 0
        for i in range(self.header.num_files):
            fileHdr = f.read(30)
            fileHdr = struct.unpack("<BHLLLLLHHBBB", fileHdr)
            ln = fileHdr[-1]
            name = f.read(ln+1)
            name = name.decode(self.encoding)
            if name[-1:] != '\x00':
                print(u"Invalid file name last character: {0!r} for {1}".format(name[-1], name[:-1]))
            name = name[:-1]
            assert(len(name) == ln)
            fileFtr = f.read(12)
            fileFtr = struct.unpack("<LLL", fileFtr)
            fileEntry = FileEntry(*(fileHdr + (name, ) + fileFtr), dirs=self.dirs, archive=self)
            files.append(fileEntry)
            assert(fileEntry.entry_size == 43 + fileEntry.name_size)
            pos += fileEntry.entry_size
        assert(pos == self.header.files_list_size)
        self.files = files

    def __iter__(self):
        if self.files is None:
            self.load_files()

        return self.files.__iter__()

def debug(fl):
    arc = Archive(fl)

    print(arc.header)
    print(arc.header.datetime)

    for d in arc.dirs:
        print(repr(d))
    
    for fe in arc:
        print(repr(fe))
        print(fe.datetime, fe.attributes)

def filter_list(all_files, archive, files=None):
    if files is None:
        files = archive
    first = True
    for f in files:
        if all_files or (f.is_in_part(archive) and (not f.split or first)):
            first = False
            yield f

def list_files(archive, all_files=False, patterns=None, encoding=None, **kwargs):
    if patterns is None:
        patterns = list()

    # Lower everything as these archive are Windows style and not case sensitive
    patterns = list(map(str.lower, patterns))

    arc = Archive(archive, encoding)

    total_original_size = 0
    total_compacted_size = 0
    num_files = 0

    print(u' {0:<8} {1:<5} {2:<8} {3:<4} {4:<8} {5:<4}'.format('Date','Time','OrigSize', 'Attr', 'CompSize', 'Name'))
    print(u' {0:=<8} {0:=<5} {0:=<8} {0:=<4} {0:=<8} {0:=<4}'.format(''))
    for f in filter_list(all_files, arc):
        for pattern in patterns:
            if fnmatch.fnmatch(f.path.lower(), pattern):
                break
        else:
            # No pattern matched: continue to next file entry
            if len(patterns):
                continue
        
        print(u'{0!s}'.format(f))

        num_files += 1
        total_original_size += f.original_size
        total_compacted_size += f.compacted_size

    print(u' {0: <8} {0: <5} {0:-<8} {0: <4} {0:-<8} {0:-<9}'.format(''))
    print(u' {0: <8} {1: <5} {2: <8} {3: <4} {4: <8} {5: <9}'.format('','','OrigSize', '', 'CompSize', 'FileCount'))
    print(u' {0: <8} {0: <5} {0:-<8} {0: <4} {0:-<8} {0:-<9}'.format(''))
    print(u' {0: <8} {1: <5} {2: >8} {3: <4} {4: >8} {5: >9}'.format('','',total_original_size, '', total_compacted_size, num_files))

def extract_files(archive, directory, all_files=False, patterns=None, encoding=None, **kwargs):
    if patterns is None:
        patterns = list()

    # Lower everything as these archive are Windows style and not case sensitive
    patterns = list(map(str.lower, patterns))

    arc = Archive(archive, encoding)
    # Ensure we load the main part of the archive to have correct entries
    main_arc = arc.get_part(1)

    total_original_size = 0
    total_compacted_size = 0
    num_files = 0

    print(u' {0:<8} {1:<5} {2:<8} {3:<4} {4:<8} {5:<4}'.format('Date','Time','OrigSize', 'Attr', 'CompSize', 'Name'))
    print(u' {0:=<8} {0:=<5} {0:=<8} {0:=<4} {0:=<8} {0:=<4}'.format(''))
    for f in filter_list(all_files, arc, main_arc):
        for pattern in patterns:
            if fnmatch.fnmatch(f.path.lower(), pattern):
                break
        else:
            # No pattern matched: continue to next file entry
            if len(patterns):
                continue
        
        print(u'{0!s}'.format(f))
        f.extract(directory)
        
        num_files += 1
        total_original_size += f.original_size
        total_compacted_size += f.compacted_size

    print(u' {0: <8} {0: <5} {0:-<8} {0: <4} {0:-<8} {0:-<9}'.format(''))
    print(u' {0: <8} {1: <5} {2: <8} {3: <4} {4: <8} {5: <9}'.format('','','OrigSize', '', 'CompSize', 'FileCount'))
    print(u' {0: <8} {0: <5} {0:-<8} {0: <4} {0:-<8} {0:-<9}'.format(''))
    print(u' {0: <8} {1: <5} {2: >8} {3: <4} {4: >8} {5: >9}'.format('','',total_original_size, '', total_compacted_size, num_files))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Decompress InstallShield .Z archives')
    parser.add_argument('archive', type=str, help="The archive to decompress")
    parser.add_argument('patterns', type=str, nargs='*', metavar="file", help="Optional glob to specify which files to extract")
    parser.add_argument('-l', '--list', action='store_true', help="List files instead of extracting them")
    parser.add_argument('-a', '--all', dest='all_files', action='store_true', help="Treat all files even when not in this part of the archive")
    parser.add_argument('-C', '--directory', type=str, default=".", metavar="DIR", help="Change to DIR before extracting files")
    parser.add_argument('-e', '--encoding', type=str, default='Windows-1252', help="Specify the encoding used by the archive (default: Windows-1252)")
    args = parser.parse_args()
    if False:
        debug(args.archive)
    if args.list:
        list_files(**vars(args))
    else:
        extract_files(**vars(args))

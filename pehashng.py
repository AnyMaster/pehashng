#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PeHashNG, Portable Executable hash of structural properties

@author: AnyMaster
https://github.com/AnyMaster/pehashng
"""

from bz2 import compress
from hashlib import sha256
from struct import pack
import logging

from pefile import PE, PEFormatError

__version__ = '0.8.1'
__author__ = 'AnyMaster'


def align_down_p2(number):
    # type: (int) -> int
    return 1 << (number.bit_length() - 1) if number else 0


def align_up(number, boundary_p2):
    # type: (int, int) -> int
    assert boundary_p2 == align_down_p2(boundary_p2)
    boundary_p2 -= 1
    return (number + boundary_p2) & ~ boundary_p2


def pehashng(pe_file):
    """ Return pehashng for PE file, sha256 of PE structural properties.

    :param pe_file: file name or instance of pefile.PE() class
    :return: SHA256 in hexdigest format, None in case of pefile.PE() error
    :rtype: str
    """

    if isinstance(pe_file, PE):
        exe = pe_file
    else:
        try:
            exe = PE(pe_file, fast_load=True)
        except PEFormatError:
            logging.exception("Exception in pefile:")
            return

    data = list()
    # Image Characteristics
    data.append(pack('> H', exe.FILE_HEADER.Characteristics))

    # Subsystem
    data.append(pack('> H', exe.OPTIONAL_HEADER.Subsystem))

    # Section Alignment, rounded down to power of two
    data.append(
        pack("> I", align_down_p2(exe.OPTIONAL_HEADER.SectionAlignment)))

    # File Alignment, rounded down to power of two
    data.append(
        pack("> I", align_down_p2(exe.OPTIONAL_HEADER.FileAlignment)))

    # Stack Commit Size, rounded up to page boundary size,
    # in PE32+ is 8 bytes
    data.append(
        pack("> Q", align_up(exe.OPTIONAL_HEADER.SizeOfStackCommit, 4096)))

    # Heap Commit Size, rounded up to page boundary size,
    # in PE32+ is 8 bytes
    data.append(
        pack("> Q", align_up(exe.OPTIONAL_HEADER.SizeOfHeapCommit, 4096)))

    # Image Directory Entry, bit flags, 1 when VA is not 0
    # entries with index 7, 8, 15 are ignored
    dirs_status = 0
    for idx in range(min(exe.OPTIONAL_HEADER.NumberOfRvaAndSizes, 16)):
        if exe.OPTIONAL_HEADER.DATA_DIRECTORY[idx].VirtualAddress:
            dirs_status |= (1 << idx)
    data.append(pack('> H', dirs_status & 0b0111111001111111))

    # Section structural information, sorted by VA by pefile
    for section in exe.sections:
        # Virtual Address, rounded up
        data.append(pack('> I', align_up(section.VirtualAddress, 512)))

        # Size Of Raw Data, rounded up
        data.append(pack('> I', align_up(section.SizeOfRawData, 256)))

        # Section Characteristics, 24 lower bits must be discarded
        data.append(pack('> B', section.Characteristics >> 24))

        # Kolmogorov Complexity, len(Bzip2(data))/len(data)
        # (0..1} ∈ R   ->  [0..8] ⊂ N
        complexity = 0
        if section.SizeOfRawData:
            complexity = (
                len(compress(section.get_data())) * 7.0 / section.SizeOfRawData)
            if complexity > 7:
                complexity = 8
            else:
                complexity = int(round(complexity))
        data.append(pack("> B", complexity))

    if not isinstance(pe_file, PE):
        exe.close()

    return sha256("".join(data)).hexdigest()


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print "Usage: pehashng.py path_to_file"
        sys.exit(0)
    print pehashng(sys.argv[1]), sys.argv[1]

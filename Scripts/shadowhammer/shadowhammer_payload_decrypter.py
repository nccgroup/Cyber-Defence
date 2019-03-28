"""
Author: Nikolaos P, NCC Group
  Date: March 2019

Decrypt the shadowhammer payload. Tested with the sample documented
by Kaspersky 55A7AA5F0E52BA4D78C145811C830107.
"""

import argparse
import logging
import struct
import sys
from copy import copy

import pefile

# Enforce Python 3 due to changes in how byte arrays work (making it
# work in Python 2 is left as an exercise for the user..)
MIN_PYTHON = (3, 0)
if sys.version_info < MIN_PYTHON:
    sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)


def mask8(value):
    return value & 0xFF


def mask32(value):
    return value & 0xFFFFFFFF


def get_resource_data(pe, name):
    """
    Obtain a copy of the data for a particular resource.
    """

    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if str(rsrc.name) == name:
            for res in rsrc.directory.entries:
                data_rva = res.directory.entries[0].data.struct.OffsetToData
                size = res.directory.entries[0].data.struct.Size
                return pe.get_memory_mapped_image()[data_rva : data_rva + size]

    return None


def decode(data, len_of_data):
    """
    Implements the byte manipulation from original Shadowhammer sample.
    """
    out = []

    (initial,) = struct.unpack("I", data[:4])
    i = copy(initial)
    j = copy(initial)
    k = copy(initial)
    l = copy(initial)

    pos = 0
    while pos < len_of_data:
        i = mask32(i + ((i) >> 3) - 0x11111111)
        j = mask32(j + (j >> 5) - 0x22222222)
        k = mask32(k + ((0x33333333 - (mask32(k << 7)))))
        l = mask32(l + mask32(0x44444444 - (mask32(l << 9))))
        result = mask8(l) + mask8(k) + mask8(j) + mask8(i)
        result = result ^ (data[pos])
        result = bytes([mask8(result)])
        out.append(result)
        pos += 1

    return b"".join(out)


def main():
    parser = argparse.ArgumentParser(description="Decode Shadowhammer payload")

    parser.add_argument(
        "--input", type=str, help="input Shadowhammer sample (PE)", required=True
    )
    parser.add_argument(
        "--output", type=str, help="output decoded payload file", required=True
    )
    args = parser.parse_args()

    try:
        pe = pefile.PE(args.input)
    except Exception:
        logging.error("Could not parse input file as a Portable Executable")
        sys.exit(1)

    encoded_data = get_resource_data(pe, "EXE")

    if encoded_data is None:
        logging.error("Couldn't find a resource named 'EXE'")
        sys.exit(1)

    if len(encoded_data) < 16:
        logging.error("Not at least 16 bytes for header data")
        sys.exit(1)

    # Decode the 16 byte header, the third DWORD specifies the length of the
    # final payload.
    header = decode(encoded_data, 16)
    (encoded_size,) = struct.unpack("I", header[8:12])
    encoded_size += 0x10
    logging.debug("Header specifies %d bytes of encoded payload", encoded_size)

    if len(encoded_data) < encoded_size:
        logging.error("Not enough data in the buffer to decode")
        sys.exit(1)

    # Decode the remaining payload
    payload = decode(encoded_data, encoded_size)

    with open(args.output, "wb") as f:
        f.write(payload)


if __name__ == "__main__":
    main()

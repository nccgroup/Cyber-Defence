#!/usr/bin/env python

import sys
import re

########
# Author: David Cannings <david.cannings@nccgroup.com>
#   Date: May 2016
#
# Extract the embedded payloads from a Sakula dropper, decode
# with XOR and save to disk.
#
# See the accompanying technical note for further information.
#######

def xor(data, key):
    """ Standard non-null, non-key XOR """

    out = ""

    for c in data:
        if ord(c) != 0 and c != key:
            c = chr(ord(c) ^ ord(key))

        out += c

    return out


def find_xor_key(data):
    """ Identify the XOR byte from the original executable """

    # Find the XOR decode loop, which is:
    #
    # test al, al; jz ..; cmp al, <byte>; jz ..; xor al <byte>
    #
    # Confirm it's a likely match by requiring both bytes to be the same.
    #
    # Note that using Yara from Python is a more efficient mechanism to
    # use at scale (and saner to read..).
    for match in re.finditer(r"\x84\xC0\x74\x08\x3C(.)\x74\x04\x34\1", data):
        print "Found likely XOR key byte '{}' at {}".format(match.group(1), match.start())
        return match.group(1)

    return None


def find_markers(data):
    """ Find all instances of 8 character file markers """

    markers = []

    for match in re.finditer(r"([A-Z])\1{7}", data):
        # Check the preceding byte is null.
        if data[match.start() - 1: match.start()] != "\x00":
            print "Skipping, doesn't pass sanity check"
            continue

        text = match.string[match.start():match.end()]

        print "Found a match at offset {}, string: {}".format(
            match.start(), text)

        markers.append({ 'text': text, 'offset': match.start() })

    return markers


def save_data(data, fn, key):
    """ Decode and save data to disk """

    data = xor(data, key)

    with open(fn, 'wb') as fh:
        fh.write(data)


def extract_data(data, markers, fn, key):
    """ Extract the relevant portion of data from the dropper """

    for index, obj in enumerate(markers):
        start = obj['offset'] + 8

        # Is this the last marker in the file?
        if index < len(markers) - 1:
            # Extract to start of next marker
            end = markers[index + 1]['offset']
        else:
            # Extract to end of data
            end = None

        # Output filename made from input + marker
        name = "{}-{}".format(fn, obj['text'])

        save_data(data[start:end], name, key)


def main():
    if len(sys.argv) != 2:
        print "Usage: {} <input file>".format(sys.argv[0])
        sys.exit(1)

    fn = sys.argv[1]

    try:
        with open(fn, 'rb') as fh:
            data = fh.read()

            print "Loaded file, length of data is: {}".format(len(data))

            xor_key = find_xor_key(data)

            if xor_key is None:
                print "Couldn't find XOR key in this file, is this a Sakula dropper?"
                sys.exit(1)

            markers = find_markers(data)
            print "Found {} potential files to extract".format(len(markers))

            extract_data(data, markers, fn, xor_key)

    except IOError:
        print "Could not open file: {}".format(fn)


if __name__ == "__main__":
    main()

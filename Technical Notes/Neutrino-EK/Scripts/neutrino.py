#!/usr/bin/python

########
# Author: Cedric Halbronn <cedric.halbronn@nccgroup.com>
# Date: July 2016
# 
# mak (@maciekkotowicz) published a script to extract exploits from the Neutrino EK.
# It is based on the pyswf library to manipulate the SWF, its binary data and scripts. It automates 
# extracting all components from the original Flash file
# 
# The algorithm is the following:
# - Parse stage1 binary data and get the one with digits before encrypted data. This is the encrypted
#   configuration file.
# - Retrieve strings from stage1 script between writeBytes and Loader . They correspond to the different
#   encrypted blobs that form encrypted stage2.
# - Parse stage1 binary data and get the blobs that are less than 0x50. They are candidate for the key to
#   decrypt stage2.
# - Decrypt stage2 with previous candidate key until we get a valid Flash header (ZWS, CWS or FWS)
# - Retrieve strings from stage2 script that are the concatenation of at least 5 letters with at least 4
#   digits. We should get two results: one is an RC4 key to decrypt the exploits and the other is an RC4
#   key to decrypt the configuration file.
# - The key that works both for decrypting one HTML exploit and ZLIB decompressing it can be used to
#   decrypt all other exploits.
# - The other key is used to decrypt the configuration file
# 
# Tested on Ubuntu 14.04.2 64-bit and Windows 8.1 with Python 2.7 32-bit
#
# Windows dependencies:
# pip install wheel
# libxml2 (lxml-3.6.1-cp27-cp27m-win32.whl from http://www.lfd.uci.edu/~gohlke/pythonlibs/#lxml)
# easy_install pycrypto
# easy_install pyswf
#
# TODO:
# - original script describes itself as Nuclear SWF decoder so worth trying on Nuclear EK as well?
#
# Changes
# - 2016/07/17: original script from https://github.com/mak/ekdeco/blob/master/neutrino/neutrino.py
# - 2016/07/19: save exploits with their internal names
########

import re
import sys
import zlib
import json
import hashlib
import argparse
import StringIO
import os
import pprint
from swf.movie import SWF
from Crypto.Cipher import ARC4

rc4_decrypt = lambda d,k : ARC4.new(k).decrypt(d)
deflate_decompress = lambda d : zlib.decompress(d, -15)

# http://stackoverflow.com/questions/16888409/suppress-unicode-prefix-on-strings-when-using-pprint
def my_safe_repr(object, context, maxlevels, level):
    typ = pprint._type(object)
    if typ is unicode:
        object = str(object)
    return pprint._safe_repr(object, context, maxlevels, level)
printer = pprint.PrettyPrinter()
printer.format = my_safe_repr

def get_extension(ek_name):
    if "html_rc4" in ek_name:
        return ".html_"
    if "js_rc4" in ek_name:
        return ".js_"
    if "swf_rc4" in ek_name:
        return ".swf_"

class Neutrino(SWF):

    # Return a dictionary of characterIds to their defining swf.tag.TagDefineBinaryData.
    # The DefineBinaryData tag permits arbitrary binary data to be embedded in a SWF file.
    # @see https://github.com/timknip/pyswf/blob/master/swf/tag.py
    @property
    def binary_data(self):
        if not hasattr(self, '_bd'):
            self._bd = self.build_dictionary()
        return self._bd

    # Return a list of swf.data.SWFSymbol
    # @ see https://github.com/timknip/pyswf/blob/master/swf/data.py
    @property
    def symbols(self):
        if not hasattr(self, '_sc'):
            # self.tags is a list of TagFileAttributes.
            # The FileAttributes tag defines characteristics of the SWF file.
            # @see https://github.com/timknip/pyswf/blob/master/swf/tag.py
            for s in self.tags:
                if s.name == 'SymbolClass':
                    self._sc = s
                    break
        return self._sc.symbols

    # Return a swf.tag.TagDoABC or swf.tag.TagDoAction object
    # XXX - what does it contain?
    @property
    def script(self):
        if not hasattr(self, '_s'):
            for s in self.tags:
                if s.name in ['DoABC','DoAction']:
                    self._s = s
                    break
        return self._s

    # Return a SWFSymbol object associated with a given blob name
    def tag_by_name(self, name):
        for s in self.symbols:
            if s.name.endswith(name):
                return self.binary_data[s.tagId]
        return None

    def symbol_by_id(self, id_):
        for s in self.symbols:
            if s.tagId == id_:
                return s.name
        return None

    # Get exploits from the 2nd SWF file
    def get_exploits(self):
        for id_, tag in self.binary_data.items():
            d = rc4_decrypt(tag.data, self.ek_key)
            # decompress other file types such as HTML, JS
            if d[:3] not in ['ZWS','CWS','FWS']:
                d = deflate_decompress(d)
            yield id_, d

    # Get keys from the 2nd SWF file
    def get_keys(self):
        data_id = [s.tagId for s in self.symbols if 'html_rc4' in s.name][0]
        keys_list = re.findall('[a-z]{5,}[0-9]{4,}', self.script.bytes)
        # XXX - should there be only 2 keys here?
        # One can be used to decrypt an HTML blob, the other one is the cfg key?
        for k in keys_list:
            try:
                d  = rc4_decrypt(self.binary_data[data_id].data, k)
                d  = deflate_decompress(d)
                self.ek_key = k
            except Exception as e:
                self.cfg_key = k

    def get_data(self, t):
        ''' In case we have some leftovers in resource names...'''
        try:
            return self.tag_by_name(t).data
        except:
            return ''

    def get_second_swf(self):
        # get encrypted data
        if 'as$7:anonymous' in self.script.bytes:
            # XXX - is this part of an old EK?
            print("[!] as$7:anonymous used")
            resources = []
            for i, g in enumerate(re.finditer('[a-zA-Z]+\.as\$[0-9]{1,2}:anonymous',self.script.bytes)):
                x = re.findall('[a-zA-Z0-9]{5,}', self.script.bytes[g.start()-40:g.start()])
                resources.append(x[0] if 'ByteArray' in x else x[-1])
        else:
            # get all the strings in the Action Script
            strs = re.findall('[a-zA-Z0-9]{5,}', self.script.bytes)
            # all the blob names are found between usage of writeBytes() and Loader()
            beg = strs.index('writeBytes')
            try:
                end = strs.index('getDefinitionByName')
            except:
                end = strs.index('Loader')
            resources = [strs[beg-1]] + strs[beg+1:end]
            if len(resources) < 5:
                # this is older version with one letter-names...
                idx = self.script.bytes.index('writeBytes')
                h = re.findall('([a-z])\nwriteBytes((\x01[a-z])+)\x06Loader', self.script.bytes,re.M)[0]
                resources = [h[0]] + h[1].split("\x01")[1:]
        swf_enc_bytes = ''.join([self.get_data(r) for r in resources])
        if debug:
            print("[+] Found %d encrypted blobs used for second swf (Total = %d bytes):" % \
                  (len(resources), len(swf_enc_bytes)))
            print(resources)

        # potential key sizes are less than 0x50 in practice
        keys_list = [tag.data for id_, tag in self.binary_data.items() if len(tag.data) < 0x50]
        for k in keys_list:
            d = rc4_decrypt(swf_enc_bytes, k)
            if d[:3] in ['ZWS','CWS','FWS']:
                return d

    # XXX - what is cfg in an SWF file?
    def get_cfg(self):
        for id_, tag in self.binary_data.items():
            x = tag.data[:3]
            try:
                # cfg is the only binary blob containing digits in the first 3 characters?
                size = int(x, 16)
                res = tag.data[3:3+size]
                print('[+] cfg found in tag: %d with name: "%s"' % (id_, self.symbol_by_id(id_)))
                return res
            except:
                pass
        return None

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Neutrino Exploit Kit SWF Extractor')
    parser.add_argument('file', type=str, nargs='?', help='File path')
    parser.add_argument('-d', '--dir', help='Output dir', default='/tmp')
    parser.add_argument('-e', '--exploits', help='save exploits', default=False, action='store_true')
    parser.add_argument('-i', '--intermediate', help='save second swf', default=False, action='store_true')
    parser.add_argument('-v', '--verbose', help='display more info', default=False, action='store_true')
    args = parser.parse_args()

    debug = args.verbose

    if args.file == None:
        parser.error("You need to provide an SWF file")

    if args.dir != None:
        try:
            os.mkdir(args.dir)
        except OSError:
            print("[!] Output directory exists, overwriting existing files...")

    neutrino = Neutrino(open(args.file, 'rb'))
    cfg_r = neutrino.get_cfg()
    if cfg_r == None:
        print("[x] Could not find cfg")
        sys.exit()
    swf = neutrino.get_second_swf()
    if not swf:
        print("[x] Can't extract second swf, bailing")
        sys.exit()

    h = hashlib.sha256(swf).hexdigest()
    print('[+] Embedded SWF (SHA256: %s)' % h),
    if args.intermediate:
        p = os.path.join(args.dir, "intermediate.swf_")
        with open(p, 'wb') as f: f.write(swf)
        print('-> saved in %s' % p)
    else:
        print('')

    neutrino2 = Neutrino(StringIO.StringIO(swf))
    neutrino2.get_keys()
    if debug:
        p = os.path.join(args.dir, "swf1_bytes.txt")
        open(p, 'wb').write(neutrino.script.bytes)
        p = os.path.join(args.dir, "swf2_bytes.txt")
        open(p, 'wb').write(neutrino2.script.bytes)
    if debug:
        print('[+] cfg key: %s, exploit key: %s' % (neutrino2.cfg_key, neutrino2.ek_key))
    cfg_json_str = rc4_decrypt(cfg_r, neutrino2.cfg_key)
    cfg = json.loads(cfg_json_str)
    p = os.path.join(args.dir, "config.txt")
    open(p, 'wb').write(printer.pformat(cfg))
    if debug:
        print("[+] cfg:")
        printer.pprint(cfg)
    for id_, ek in neutrino2.get_exploits():
        h = hashlib.sha256(h).hexdigest()
        ek_name = neutrino2.symbol_by_id(id_).split("$")[0]
        print('[+] Exploit %s (SHA256: %s)' % (ek_name, h)),
        if args.exploits:
            p = os.path.join(args.dir, ek_name + get_extension(ek_name))
            with open(p,'wb') as f: f.write(ek)
            print('-> saved in %s' % p)
        else:
            print('')
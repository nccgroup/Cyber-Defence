########
# Author: Cedric Halbronn <cedric.halbronn@nccgroup.com>
# Date: July 2016
# 
# RC4-decrypts stage 2 and configuration file stored in stage 1
########

import os, binascii, pprint, json

# http://stackoverflow.com/questions/16888409/suppress-unicode-prefix-on-strings-when-using-pprint
def my_safe_repr(object, context, maxlevels, level):
    typ = pprint._type(object)
    if typ is unicode:
        object = str(object)
    return pprint._safe_repr(object, context, maxlevels, level)
printer = pprint.PrettyPrinter()
printer.format = my_safe_repr

# binaryData\ MUST contains
# 1_d.picuazscsx.bin
# 2_d.daimfxmlnvui.bin
# ...
blobs = os.listdir('binaryData')
blobs = [os.path.join('binaryData', f) for f in blobs]

# helper to get the data for a given blob name
def get_data(blobname):
    for b in blobs:
        if blobname in b:
            data = open(b, 'rb').read()
            return [ord(c) for c in data]
    print "ERROR: cannot read %s" % blobname
    return None

# helper to convert an array to a string
def array2str(array):
    s = ''
    for byte in array:
        s += chr(byte)
    return s

# looks like this is actually RC4 ...
# http://blog.cdleary.com/2009/09/learning-python-by-example-rc4/
def decrypt(param1, param2):
    print "len(param1)=%d bytes" % len(param1)
    print "len(param2)=%d bytes" % len(param2)
    i1 = 0
    i2 = 0
    j = 0
    _arr2 = []
    _arr1 = [i1 for i1 in range(256)]
    for i1 in range(256):
        j = (j + _arr1[i1] + param1[i1 % len(param1)]) & 0xff
        k = _arr1[i1]
        _arr1[i1] = _arr1[j]
        _arr1[j] = k
    j = 0
    i1 = 0
    for i2 in range(len(param2)):
        i1 = (i1 + 1) & 0xff
        j = (j + _arr1[i1]) & 0xff
        k = _arr1[i1]
        _arr1[i1] = _arr1[j]
        _arr1[j] = k
        _arr2.append(param2[i2] ^ _arr1[(_arr1[i1] + _arr1[j]) & 0xff])
    return array2str(_arr2)

# first call to decrypt()
def decrypt_strings():
    rmyrxhyabwygug = get_data('rmyrxhyabwygug')
    meqlxhywzvdyv = get_data('meqlxhywzvdyv')
    if not rmyrxhyabwygug or not meqlxhywzvdyv:
        print "Cant read files"
        sys.exit()
    res = decrypt(rmyrxhyabwygug, meqlxhywzvdyv)
    # should be: "loadBytes;removeEventListener;stage;contentLoaderInfo;addChild;addEventListener"
    print res

# second call to decrypt()
def decrypt_embedded_flash_file(outfile='stage2.swf_'):
    _loc35_ = get_data('iecqnvmtbfwkz') + get_data('rrazhdfpslkf') + get_data('xsloaqqqdldwnit') + get_data('ifpafpijuxcghif') + get_data('artahkrkwuh') + get_data('daimfxmlnvui') + get_data('xoafugflzgskxd') + get_data('skrvlzirxvd') + get_data('qysjvhjabpgm') + get_data('mfakihctyyfxh')
    _loc50_ = get_data('rmyrxhyabwygug')
    if not _loc50_ or not _loc35_:
        print "Cant read files"
        sys.exit()
    res = decrypt(_loc50_, _loc35_)
    if res[:3] == 'CWS':
        print "Succesfully decrypting Flash file. Writing into %s" % outfile
        open(outfile, 'wb').write(res)
    else:
        print "Failed decrypting Flash file"

# this is actually done in stage2.swf
def decrypt_cfg(outfile='cfg.txt'):
    picuazscsx = get_data('picuazscsx')
    size_cfg = int(array2str(picuazscsx[:3]), 16)
    picuazscsx = picuazscsx[3:3+size_cfg]
    if not picuazscsx:
        print "Cant read files"
        sys.exit()
    key = "kpbbwoff17384" # from stage2 mainClass.et()
    key = [ord(c) for c in key]
    res = decrypt(key, picuazscsx)
    cfg = json.loads(res)
    open(outfile, 'wb').write(res)
    pprint.pprint(cfg)

if __name__ == '__main__':
    decrypt_strings()
    decrypt_embedded_flash_file()
    decrypt_cfg()
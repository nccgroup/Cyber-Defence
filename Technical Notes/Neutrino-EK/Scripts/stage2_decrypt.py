########
# Author: Cedric Halbronn <cedric.halbronn@nccgroup.com>
# Date: July 2016
# 
# RC4-decrypts all blobs stored in stage 2
#
# TODO:
# XXX
########

import os, binascii, sys

# binaryData\ MUST contains
# 1_nw22_swf_rc4$341acf8a38c7ef2cbe35c674750c202b-394312611.bin
# 2_nw23_swf_rc4$ff09886f44cb2db0af6cdbff7a01061f2083705692.bin
# ...
blobs = os.listdir('binaryData')
blobs_paths = [os.path.join('binaryData', f) for f in blobs if f.endswith(".bin")]
out_paths = []
for f in blobs_paths:
    out_paths.append(f.rsplit("$")[0] + ".txt")

# helper to get the data for a given blob name
def get_data(blobname):
    for b in blobs_paths:
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

def decrypt_all():
    key = "edfdamtlkfg511485"
    key = [ord(c) for c in key]
    for i in range(len(blobs_paths)):
        data = get_data(blobs_paths[i])
        res = decrypt(key, data)
        print "Writing %d bytes" % len(res)
        open(out_paths[i], 'wb').write(res)
    #    print res[:10]
    
if __name__ == '__main__':
    decrypt_all()
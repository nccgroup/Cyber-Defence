########
# Author: Cedric Halbronn <cedric.halbronn@nccgroup.com>
# Date: July 2016
# 
# ZLIB-decompress some blobs stored in stage 2
########

import sys, zlib

deflate_decompress = lambda d : zlib.decompress(d, -15)

if len(sys.argv) != 3:
    print("Usage: %s <infile> <outfile>" % (sys.argv[0]))
    sys.exit()

infile = sys.argv[1]
outfile = sys.argv[2]
data = open(infile, 'rb').read()
data = deflate_decompress(data)
open(outfile, 'wb').write(data)
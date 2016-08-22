########
# Author: Cedric Halbronn <cedric.halbronn@nccgroup.com>
# Date: July 2016
# 
# Replaces decrypted strings in stage 1 decompiled source code
########

import sys

# obtained by using decrypt_strings() from stage1_decrypt.py
this_x = "loadBytes;removeEventListener;stage;contentLoaderInfo;addChild;addEventListener".split(";")

data = open('owaugjojgtx_deobfuscated_renamed.as', 'rb').read()
for i in range(len(this_x)):
    data = data.replace("this.x[%d]" % i, '"%s"' % this_x[i])
open('owaugjojgtx_deobfuscated_renamed_replaced.as', 'wb').write(data)
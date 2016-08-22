########
# Author: Cedric Halbronn <cedric.halbronn@nccgroup.com>
# Date: July 2016
# 
# XOR-decrypts the shellcode
# This mimics the 1-byte XOR decryption routine implemented in the shellcode
########

import sys

infile = '1_shell_rc4_decrypted_1.txt'
outfile = '1_shell_rc4_decrypted_2.txt'
payload_offset = 0x19
data = open(infile, 'rb').read()
data = data[payload_offset:]
payload_length = len(data)
print "payload length = 0x%x bytes" % payload_length
i = 0
data_dec = ''
while i < payload_length:
    data_dec = data_dec + chr(ord(data[i]) ^ 0x9A)
    i += 1
open(outfile, 'wb').write(data_dec)
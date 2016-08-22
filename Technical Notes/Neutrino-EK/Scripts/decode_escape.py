########
# Author: Cedric Halbronn <cedric.halbronn@nccgroup.com>
# Date: July 2016
# 
# Attempt to decode the output of Action Script trace(escape()) (does not work yet).
# This is because some characters are not decoded correctly. E.g.: we got a %CC after using escape()
# which ended up being decoded as byte 0xCC whereas the result should have been two bytes 0xC3 0x8C . 
# It is not clear why we got this result though.
#
# TODO:
# We have attempted a methodology based on trace() to dump binary data. It would be interesting to be
# able to dump any binary content using this method. It would be worth trying to use the Action Script
# unescape() to decode content that has been encoded with escape() 
########

import sys, binascii, pickle
import urllib, re, base64

outfile = "stage2_2_unicode.swf"

# COPY HERE result from trace(escape())
s = "CWS%20%C4%06%01%00x%DA%u073CwX%13%DB%F3%07%BC%9B%B6%09%3D%01%05%E9%60%28%81%D0%3BX%28%8A%88%0A%0A%16T@%92%90%u040B%24%88%0D%05%15%BBWE%04%DBU%B1wQ%AC%F7Z%E8%D8%09A%C0%82%BD%F7%EE%B5%F3%CE%D9%0D%B6%7B%DF%EF%F3%FB%E3%FD%EB%95%27gw%CF%u0319%D3f%E63sv%1F%27b%8C%DB%18%A6%B3%05%CCp..."

# Does the contrary of escape() excepts it does not support unicode characters
# The above string is converted to 'CWS \xc4\x06\x01\x00x\xda%u073C..'
# We can see remaining %uXXXX which are encoded using unicode
t = urllib.unquote(s)

# Handle the remaining %uXXXX
uni_list = re.findall("%u([0-9a-fA-F]{4})", t)
#print "Found %d instances" % len(uni_list)
uni_list = set(uni_list)
print "Really %d unique instances" % len(uni_list)

#d = {}
for i_str in uni_list:
	# i_str = "073C" so get the int value 0x073C
	# u_src = unicode string with ordinal <= 0x10ffff i.e. u'\u073c'
	# dstarr = a sequence of bytes i.e. bytearray(b'\xdc\xbc')
	# dst = raw data which is type "str" i.e. '\xdc\xbc'
	src = int(i_str, 16)
	u_src = unichr(src)
	dstarr = bytearray(u_src, encoding="utf8")
	dst = str(dstarr)
    
	t = t.replace("%u" + i_str, dst)
	#d[i_str] = binascii.hexlify(dstarr)

print "Writing output file: %s" % outfile
open(outfile, "wb").write(t)

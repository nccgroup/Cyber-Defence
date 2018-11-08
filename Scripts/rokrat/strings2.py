########
# Author: Nikolaos P, NCC Group
#   Date: August 2018
#
# Decrypt strings from a Rokrat sample.  See the NCC Group blog
# for further information.
########

def getbyte(dwordn, n):
	return int((dwordn&(0xFF<<(8*n)))>>(8*n))	

def getbytes(dwordn, off1, off2, key):    
	return (getbyte(dwordn, off1) - key) & 0xFF, (getbyte(dwordn, off2) - key) & 0xFF
	
encrypted_str = [0x8A90884,0x8E308E8,0x8E808A9,0x8A908B2,0x8B208E8,0x8E808A9]

key =  int(encrypted_str[0] & 0xFF)

result = ""

for i in range(0,len(encrypted_str),1):	    
	byte1, byte2 = getbytes(encrypted_str[i], 2, 0, key)    
	result += chr(byte2) + chr(byte1)
	
print result[1:]
########
# Author: Nikolaos P, NCC Group
#   Date: August 2018
#
# Decrypt strings from a Rokrat sample.  See the NCC Group blog
# for further information.
########

def getword(getdwordn, n):
    return int((getdwordn&(0xFFFF<<(16*n)))>>(16*n))	
	
encrypted_str = [0x8FB08D6,0x9460939,0x93A093F,0x8FB0910,0x902093A,0x9370944,0x93B0943,0x8FB0910,0x9020949,0x9370946,0x93E094A,0x8FB0910,0x8FB0949,0x939]	

key = int(encrypted_str[0] & 0xFF)

result = ""

for item in encrypted_str:    
	for p in range(2):        
		sub1 = getword(item,p)
		if(sub1==0):            
			continue        
		result += unichr( (sub1 - key)- 0x800)

print result[1:]
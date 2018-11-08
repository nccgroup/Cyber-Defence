########
# Author: Nikolaos P, NCC Group
#   Date: August 2018
#
# Decrypt strings from a Rokrat sample.  See the NCC Group blog
# for further information.
########

def getbyte(dwordn, n):
	return int((dwordn&(0xFF<<(8*n)))>>(8*n))	

#encrypted string example
encrypted_str = [0x92A08E1,0x9380954,0x9580950,0x9150917,0x9530931,0x9440950,0x9540946,0x954]

result = ""

for i in range(0,len(encrypted_str),1):
	
	num1 = getbyte(encrypted_str[i],0)+0x1F
		
	num2 =  getbyte(encrypted_str[i],2)+0x1F
	result+=unichr(num1)
	result+=unichr(num2)

print result[1:]

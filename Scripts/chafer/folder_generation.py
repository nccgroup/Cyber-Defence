'''
Author: Nikolaos P.
Purpose: Generate folder's name as Chafer does
'''

import random

def generate_folder_name(a1,a2):
	rand_sum = 0
	folder_name = ""
	string1 = "{????????-????-????-????-????????????}"
	random.seed(a2)
	for i in string1:
		if(i=="?"):
			randresult = random.randint(0, 2147483647)%16
			rand_sum = 87
			if(randresult<10):
				rand_sum = 48
			i = randresult+rand_sum
			folder_name+=chr(i)
		else:
			folder_name+=i
	print folder_name
generate_folder_name(0,0x6F360)
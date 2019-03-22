'''
Author: Nikolaos P.
Purpose: Replicate the update key algorithm which Chafer uses.

'''

received_data = ""
counter=0
new_key = [0]*0x54 #init
for i in range(len(received_data)):

		add1= ( ord(received_data[i]) +ord(received_data[-(i+1)]) )%255
		
		new_key[counter+2]=hex(add1)
		new_key[counter] = received_data[-(i+1)].encode('hex')
		new_key[counter+1] = received_data[i].encode('hex')
		counter+=3
		
		
print new_key

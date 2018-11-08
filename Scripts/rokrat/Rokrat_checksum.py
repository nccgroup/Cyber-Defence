'''
TITLE: RokRat_checksum
AUTHOR: Nikolaos P, NCC Group
DESCRIPTION: Calculate the checksum of a process's name as RokRat does.
VERSION: 1.00
DATE: 17/08/2018
HASHES: 4d37f80da97845129debf3244e1f731d2c93a02519f9fdaa059f5f124cf7c26f
'''

def checksum(process_name):
	first_hardcoded = 0x1505
	result = 0
	for i in process_name:
		if (ord(i)-0x61) & 0xFFFF<0x19:
			addition = (ord(i)+0xFFE0) & 0xFF
			#print("MORE addition is 0x{:04X}".format(addition))
		else:
			addition = ord(i)
			#print("LESS addition is 0x{:04X}".format(addition))

		shiftl = (first_hardcoded<<5)&0xFFFFFFFF
		#print("shiftl is 0x{:08x}".format(shiftl))
		add1 = (first_hardcoded + shiftl) &0xFFFFFFFF
		#print("add1 is 0x{:08x}".format(add1))
		result = (add1 + addition)& 0xFFFFFFFF
		#print("result is 0x{:08x}".format(result))
		#print("***")
		first_hardcoded = result

	return result

def rotate(c):
	val = ord(c)
	ripple = False
	new = None

	if val == 57: # ord('9'):
		new = 'A'
	elif val == 90: # ord('Z'):
		new = 'a'
	elif val == 122: # ord('z'):
		new = '0'
		ripple = True
	else:
		new = chr(val + 1)

	return (new, ripple)

def list_increment(chars, max_length=10):

	new = list(chars)
	length = len(chars)

	for idx,char in reversed(list(enumerate(chars))):
		(char, ripple) = rotate(char)
		new[idx] = char
		if not ripple:
			break

		if idx == 0:
			if length == max_length:
				raise StopIteration
			
			new.insert(0, '0')
			print("Incrementing, now {} characters".format(len(new)))

	return new

def main():
	data = [ '0' ]

	checksum("smss.exe")
	val = checksum("gbb.exe")
	print("hash is 0x{:08x}".format(val))
	import sys
	sys.exit(1)

	n = 0

	import time
	last = time.time()
	hashes = 0

	while True:
		try:
			data = list_increment(data, max_length = 4)
		except StopIteration:
			print("Reached the end, data is: {}".format(data))
			break

		candidate = "{}.exe".format("".join(data))
		val = checksum(candidate)
		if val in [ 0x3e41d9b, 0xFBDFAC40, 0x8BA5B4C5 ]:
			print("FOUND A MATCH! Input {} matches hash 0x{:08x}".format(candidate, val))
		
		hashes += 1
		now = time.time()
		interval = now - last

		if interval > 10:
			print("Current speed: {:.02f} hashes per second".format(hashes / interval))
			last = now
			hashes = 0

if __name__ == "__main__":
	main()
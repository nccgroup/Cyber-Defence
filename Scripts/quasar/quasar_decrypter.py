'''
Author: Nikolaos Pantazopoulos
Quasar RAT config decrypter.
Tested with samples from APT10 and with the latest build of Quasar RAT. 
https://github.com/quasar/QuasarRAT/releases.
'''

#!python2

try:
    import pype32
except ImportError:
    print "pype32 is reqired https://github.com/crackinglandia/pype32"

import re
from pbkdf2 import PBKDF2
import base64
import string
from Crypto.Cipher import AES
import binascii
import sys
import os
import argparse


salt = str(bytearray.fromhex('BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941')) #hardcoded

				 
#https://gist.github.com/chrix2/4171336
class PKCS7Encoder(object):
	def __init__(self, k=16):
		self.k = k

	## @param text The padded text for which the padding is to be removed.
	# @exception ValueError Raised when the input padding is missing or corrupt.
	def decode(self, text):
		'''
		Remove the PKCS#7 padding from a text string
		'''
		val = int(binascii.hexlify(text[-1]), 16)
		if val > self.k:
			raise ValueError('Input is not padded or padding is corrupt')
		return text[:len(text)-val]

	## @param text The text to encode.
	def encode(self, text):
		'''
		Pad an input string according to PKCS#7
		'''
		l = len(text)
		output = StringIO.StringIO()
		val = self.k - (l % self.k)
		for _ in xrange(val):
			output.write('%02x' % val)
		return text + binascii.unhexlify(output.getvalue())



def extractstring(string_):
	return re.search('''(?<=')\s*[^']+?\s*(?=')''', str(string_)).group().strip()

def findUSStream(pe, dir):
	for i in range(0,4):
		name = pe.ntHeaders.optionalHeader.dataDirectory[dir].info.netMetaDataStreams[i].name.value
		if name.startswith("#US"):
			return pe.ntHeaders.optionalHeader.dataDirectory[dir].info.netMetaDataStreams[i].info


def getStream(pe):
	counter = 0  

	for dir in pe.ntHeaders.optionalHeader.dataDirectory:
		if dir.name.value == "NET_METADATA_DIRECTORY":
			config = findUSStream(pe, counter)
		else:
			counter += 1
	return config
	

def extract_config_apt10(pe):
	stream_values = {2721: "Tag", 2679: "Key", 1883: "Install SubDirectory", 2062: "Install Name", \
				 2241: "Mutex",  2460: "Registry Name", 2900: "Logs directory",  3079: "Download string", \
				 1256: "Version",  1435: "C2", 1654:"Network Key", 1704: "Network auth"}
	config = {}
	for config_value in getStream(pe):
		id = config_value.items()[0][0]
		if id in stream_values.keys():
			res = extractstring(config_value)
			
			if not res:
				print "Failed to extract %s from configuration data" % stream_values[id]
				continue
				
			if id == 1654:
				print "Network key : " + res
				continue
			
			elif id == 1704:
				print "Network auth: " + res
				continue
			else:
				config[stream_values[id]] = res
	
	return config


def extract_config_standard(pe):
	config = {}
	for index, obj in enumerate(getStream(pe)):
		if 65 in obj:
			config['Version'] = extractstring(getStream(pe)[index + 1])
			config['C2'] =  extractstring(getStream(pe)[index + 2])
			print "network encryption_key: " + extractstring(getStream(pe)[index + 3])
			print "network auth: " + extractstring(getStream(pe)[index + 4])
			config['Install Directory'] =  extractstring(getStream(pe)[index + 5])
			config['Install name'] =  extractstring(getStream(pe)[index + 6])
			config['Mutex'] =  extractstring(getStream(pe)[index + 7])
			config['Registry name'] = extractstring(getStream(pe)[index + 8])
			config['Key'] =  extractstring(getStream(pe)[index + 9])
			config['Tag'] =  extractstring(getStream(pe)[index + 10])
			config['Logs directory'] =  extractstring(getStream(pe)[index + 11])
			return config


parser = argparse.ArgumentParser()
parser.add_argument("quasar_executable", help="the quasar executable file")
parser.add_argument("version", choices=["apt10", "standard"], default="standard", help= "the version of quasar to parse")
options = parser.parse_args()

quasar_file_path = os.path.abspath(options.quasar_executable)

if not os.path.exists(quasar_file_path):
	print "File does not exist"
	sys.exit()



choice = {"apt10": extract_config_apt10, "standard": extract_config_standard}

config = choice[options.version](pype32.PE(quasar_file_path))

if options.version == "apt10":
	aes_mode = AES.MODE_CFB
else:
	aes_mode = AES.MODE_CBC
	
if not config:
	print "Configuration data not found"
	sys.exit()


if "Key" not in config:
	print "Key used for configuration encryption not found!"
	sys.exit()
	
derived_key = PBKDF2(config["Key"],salt,50000)
aes_key = derived_key.read(16)

for key,value in config.iteritems():
	if key == "Key":
		continue
		
	try:
		d64_encstr = base64.b64decode(value)
		finaliv = d64_encstr[32:48]
		enc_text = d64_encstr.split(finaliv)[1]


		e = AES.new(aes_key, aes_mode, finaliv)
		print key+": "+PKCS7Encoder().decode(e.decrypt(enc_text))
	except Exception as e:
		print "Failed on key %s : %s" % (key, e)
		

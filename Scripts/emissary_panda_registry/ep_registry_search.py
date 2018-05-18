from _winreg import *
from Registry import Registry
from pyDes import *
import sys
import re
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-l", "--local", \
	help="This option searches the local registry", action='store_true')
parser.add_argument("-f", "--file", \
	help="This option searches the provided SOFTWARE file")
args = parser.parse_args()

# Identifier used for this infection at least
search_string = "HjDWr6vsJqfYb89mxxxx"

# key is first 8 chars of the key name
def get_key(key_name):
	return key_name[:8]

# iv is first 8 chars of the key name
def get_iv(key_name):
	return key_name[:8]	
	
def decrypt_values(key, iv, values):
	k = des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
	decrypted_values = []
	for value in values:
		decrypted_values.append([value[0], k.decrypt(value[1])])
	return decrypted_values
	
def output_results(results, key_name):
	print "[i] Found the following values in:"
	print "[-]", key_name, "\n"
	for value in results:
		print "[+]", value[0]+":", value[1]
		
def use_winregistry():
	local_reg = ConnectRegistry(None,HKEY_CURRENT_USER)
	registry_path = r"SOFTWARE\Classes"
	registry_key = OpenKey(local_reg, registry_path)
	num_subkeys = QueryInfoKey(registry_key)[0]
	last_modified = QueryInfoKey(registry_key)[2]
	for index in range(num_subkeys):
		subkey_name = EnumKey(registry_key,index)
		if search_string in subkey_name:
			subkey = OpenKey(local_reg, registry_path+"\\"+subkey_name)
			num_values = QueryInfoKey(subkey)[1]
			values = []
			for i in range(num_values):
				value = EnumValue(subkey,i)
				values.append([value[0],value[1]])
			output_results(decrypt_values(get_key(subkey_name), \
				get_iv(subkey_name), values), registry_path+"\\"+subkey_name)
			
def use_pythonregistry(registry_file):
	file_reg = Registry.Registry(registry_file)
	keys = file_reg.root().subkeys()
	for key in keys:
		for subkey in key.subkeys():
			if search_string in subkey.path():
				path_search = re.search("Classes\\\(.*)",str(subkey.path()))
				subkey_path = path_search.group(0)
				malicious_keyname = path_search.group(1)
				malicious_key = file_reg.open(subkey_path)
				values = []
				for value in malicious_key.values():
					values.append([value.name(),value.value()])	
				output_results(decrypt_values(get_key(malicious_keyname), \
					get_iv(malicious_keyname), values), subkey_path)
				
if args.local: 
	print "[i] Searching the local registry\n"
	use_winregistry()
elif args.file: 
	registry_file = sys.argv[2]
	print "[i] Searching the provided registry file -", registry_file, "\n"
	use_pythonregistry(registry_file)
else:
	parser.error("No action requested")

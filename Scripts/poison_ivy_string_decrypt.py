import idaapi
import idautils
import idc 

########
# Released by NCC Group in September 2017
#
# This script assists analysis of a recent Poison Ivy variant / PlugIvy sample by
# decrypting the encrypted strings.
#
# Instructions on using the script can be found on our blog.
########

__author__ = 'Ahmed Zaki'
__date__ = 'Sept - 2017'


def rol(x,n):
	return ((x << n) | (x >> (32-n))) & 0xffffffff

def get_encoded_string(addr):
    """ Retrieve the bytes at a specific address until a 0 delimeter it found 

        addr: (int) Address at which the bytes are located

        Returns:
        enc_bytes: (list) The byte array of the encrypted string.

    """
    enc_bytes = []

    while(idc.GetOriginalByte(addr) != 0) :
        enc_byte = idc.GetOriginalByte(addr)
        enc_bytes.append(enc_byte)
        addr += 1
    
    return enc_bytes

        

def get_args(addr):
    """ Retreives the passed arguments to the decryption function. We are only interested in the key
        and offset to the encrypted string.

        addr: (int) Address at which the decryption function was called.

        Returns:
        key: (int) The key used to decrypt the string.
        enc_str: (list) Byte array of encrypted string.
        ins_addr: (int) Address at which the encrypted byte array is referenced.

    """
    found = False
    foundstr = False
    foundkey = False
    while not found:
        addr = idc.PrevHead(addr)
        if idc.GetMnem(addr) == "mov" and "r8d" in idc.GetOpnd(addr,0):
            #print "[+] Found key: 0x%08x at 0x%016x" % (idc.GetOperandValue(addr,1)& 0xffffffff, addr)
            key = idc.GetOperandValue(addr,1) & 0xffffffff
            foundkey = True

        if idc.GetMnem(addr) == "lea" and "rdx" in idc.GetOpnd(addr,0):
            #print "[+] Found str: 0x%016x at 0x%016x" % (idc.GetOperandValue(addr,1), addr)
            enc_str_addr = idc.GetOperandValue(addr,1)
            enc_str = get_encoded_string(enc_str_addr)
            ins_addr = addr
            foundstr = True
        
        if foundkey and foundstr:
            found = True
    
    return key, enc_str, ins_addr

def decrypt(key,val):
    """ Decryption algorithm.

        key: (int) The key used for decryption.
        val: (list) The byte array of the encrypted string.

        Returns:
        res: (string) Decrypted ascii string.
    """

    res = ''
    for byte in val:
        ch = byte^(key&0xff)
        temp = rol(key,8)
        res += chr(ch)
        ## Sign extending the byte
        if byte & 0x80 != 0 :
             dword_add = 0xffffff00 + byte
        else:
             dword_add = byte & 0xffffffff

        key = (temp + dword_add ) & 0xffffffff

    return res





fn_addr = idc.AskAddr(idc.here(), "Enter address of string decoding function")

## check if address is valid
if (fn_addr < idc.MinEA()) or (fn_addr > idc.MaxEA()):
    idc.Warning("You have entered an invalid start address")
    idc.Exit


for ref in idautils.XrefsTo(fn_addr, flags=0):
    key, enc_str, ins_addr = get_args(ref.frm)
    dec_str = decrypt(key,enc_str)
    print "[+] Decoded String: %s " % dec_str
    idc.MakeComm(ins_addr, dec_str)









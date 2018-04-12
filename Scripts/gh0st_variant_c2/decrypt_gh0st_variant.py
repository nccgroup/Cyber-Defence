import os, pwd
import sys
import nids
from binascii import hexlify
from Crypto.Cipher import ARC4
from hexdump import hexdump

########
#   Date: April 2018
# Author: Nikolaos Pantazopoulos (reverse engineering), David Cannings (Python)
#
# Released as open source by NCC Group.
#
# Decrypts C2 from a custom RAT, based on the Gh0st source code.  Further
# processing is left as an exercise for the reader :)
#
# The C2 protocol is very simple, with the RC4 key being sent as the first
# 28 bytes of data in the packet.  If run correctly this should return plaintext
# (often encoded as UTF-16) which can be investigated to identify infected machines,
# extract executable plugins, observe interactive command shell activity etc.
#
# Argparse has not been implemented, some code changes will be required if
# the port differs from 443.  This naive script also assumes that all traffic
# on port 443 relates to the RAT (e.g. input pcap must be prefiltered first).
#
# Run like:
#
#  $ ./decrypt_gh0st_variant.py input.pcap
#
# Dependencies are pynids and hexdump.  Building pynids can be difficult, on
# Debian / Ubuntu systems the package python-nids provides the correct library.
# 
# Please see the NCC Group blog for further information on the C2 protocol.
########

end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

def alternate_case(string):
    """
    Implements the upper case / lower case transformation that is applied
    to the key before it is used for RC4.
    """
    
    out = string[0:2].upper()
    out += string[2:4].lower()
    out += string[4:8].upper()
    out += string[8:10].lower()
    out += string[10:14].upper()
    out += string[14:16].lower()
    out += string[16:20].upper()
    out += string[20:22].lower()
    out += string[22:24].upper()

    return out

def extract_key(data):
    """
    Extract the key from the data packet.  This requires at least 28
    bytes of data.
    """
    if len(data) < 28:
        raise Exception("Need at least 28 bytes of data")

    key = data[:28]
    and1 = ord(key[1]) & 0x89
    xor1 = ord(key[0]) ^ 0xAC
    and2 = xor1 & 0xCD
    xor2 = and1 ^ 0x60
    and3 = ord(key[8]) & 0xB0
    xor3 = ord(key[9]) ^ 0x8D
    and4 = xor3 & 0x64
    xor4 = and3 ^ 0xD1
    and5 = ord(key[16]) & 0xB4
    xor5 = ord(key[17]) ^ 0x91
    and6 = and5 & 0xD5
    xor6 = xor5 ^ 0x68

    out = "".join([ chr(and2), chr(xor4), chr(and6), chr(xor2), chr(and4), chr(xor6), chr(and1), chr(xor3), chr(xor5), chr(xor1), chr(and3), chr(and5) ])

    # Hexlify returns the string in lower case
    out = alternate_case(hexlify(out))

    return out


def decrypt(data):
    """
    Obtain the RC4 key and apply decryption.
    """
    
    key = extract_key(data)
    data = data[28:]

    print "Key for this frame: {}".format(key)

    cipher = ARC4.new(key)
    out = cipher.decrypt(data)
    hexdump(out)


def handleTcpStream(tcp):
    print "tcps -", str(tcp.addr), " state:", tcp.nids_state
    if tcp.nids_state == nids.NIDS_JUST_EST:
        ((src, sport), (dst, dport)) = tcp.addr
	print tcp.addr
        if dport == 443:
            tcp.client.collect = 1
            tcp.server.collect = 1

    elif tcp.nids_state == nids.NIDS_DATA:
        
        if tcp.server.count_new:
            print "Data to server"
            data = tcp.server.data[:tcp.server.count_new]
            decrypt(data)

        if tcp.client.count_new:
            print "Data to client.."
            data = tcp.client.data[:tcp.client.count_new]
            decrypt(data)

    elif tcp.nids_state in end_states:
        pass

def main():
    """
    Initialise libnids and process the pcap.  This is taken from the pynids
    example code.
    """

    nids.param("pcap_filter", "tcp")        # bpf restrict to TCP only, note
                                            # libnids caution about fragments

    nids.param("scan_num_hosts", 0)         # disable portscan detection

    nids.chksum_ctl([('0.0.0.0/0', False)]) # disable checksumming

    if len(sys.argv) == 2:                  # read a pcap file?
        nids.param("filename", sys.argv[1])

    nids.init()

    nids.register_tcp(handleTcpStream)

    # Loop forever (network device), or until EOF (pcap file)
    # Note that an exception in the callback will break the loop!
    try:
        nids.run()
    except nids.error, e:
        print "nids/pcap error:", e
    except Exception, e:
        print "misc. exception (runtime error in user callback?):", e

if __name__ == '__main__':
    main()

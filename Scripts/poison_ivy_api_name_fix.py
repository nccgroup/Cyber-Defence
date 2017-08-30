import os
import sys
import idaapi
import idautils
import idc 

########
# Released by NCC Group in August 2017
#
# This script assists analysis of a recent Poison Ivy variant / PlugIvy sample by
# fixing API names.
#
# Instructions on using the script can be found on our blog.
########

__author__ = 'Ahmed Zaki'
__date__ = 'Aug - 2017'

ENUM_ERRORS = {1:"ENUM_MEMBER_ERROR_NAME", 2:"ENUM_MEMBER_ERROR_VALUE",3:"ENUM_MEMBER_ERROR_ENUM",4:"ENUM_MEMBER_ERROR_MASK",5:"ENUM_MEMBER_ERROR_ILLV",}

class Pivy():

    def __init__(self):
        ## dict of addresses and enum ids for faster lookup

        addr = idc.AskAddr(0, "Enter the original base address of the file")
        if addr == idaapi.BADADDR:
            idc.Warning("Invalid Address please enter the correct base address")
            idc.Exit

        idc.rebase_program(addr, idaapi.MSF_FIXONCE)
        self.enums = {}
        self.start_addr = None
        self.symbols = {}

    def neg(self, val, bits):
        """
            Calculate the negative value of a 64bit address
            val: (int) An address value
            bits: (int) Bitness to use for calculation
        """
        val = val * -1
        return hex((val + (1 << bits)) % (1 << bits)).rstrip('L')

    def fixdata(self, filehandle):
        """
            Reads symbols dumped from Windbg and cleans them as much as possible.
            Returns a dict of negative address value for each API. 
            filehandle: (FileObject) A file object for a file of symbols and addresses.
        """
        result = {}
        for line in filehandle.readlines():
            address = line.split()[0]
            address = address.replace('`', '')
            symbol = line.split()[1].replace('-', '')
            if ':' in symbol:
                symbol = symbol.replace(':', '')
            if '<' in symbol:
                symbol = symbol.replace('<', '')

            result[symbol] = self.neg(int(address, 16), 64)
        return result
        
    
    def createenum(self, symbols):
        """
            Given full symbols and addresses create an enum name with the library name (the string before !)
            Some constants will fail due to weird characters in symbols used by MS. eg( `$)
            symbols: (dict) A set of symbols and addresses that have been cleaned.
        """
        enum_name = symbols.keys()[0].split('!')[0]
        enum = idc.AddEnum(0, enum_name, idaapi.hexflag())
        if enum == idaapi.BADADDR:
            print "[!] Failed to create enum: %s\n" % enum_name
            return 
        for symbol, address in symbols.iteritems():
            # "ADVAPI32!RegCreateKeyExWStub": "0xffff8007be2f89f0"
            org_symb = symbol
            symbol = str(symbol.split('!')[1].encode('utf-8'))
            symbol = symbol.strip()
            symbol = 's_'+symbol 
            address = int(address,16)
            ret = idc.AddConstEx(enum, symbol, address, -1)
            if ret !=0:
                print "[!] Failed to create constant for symbol %s - (%s). %s" % (org_symb,symbol,ENUM_ERRORS[ret])
                continue
            self.enums[address] = enum

        print "[+] Finished adding enum %s\n" % enum_name

    def make_enums(self):
        """ 
            Create the enumerations from the files. 
            This function will read all .txt files in a given directory
            and create an enum for each file.
        """

        dir_path = idc.AskStr("", "Enter full path to the directory of dumped PoisonIvy symbols")

        if not os.path.exists(dir_path):
            idc.Warning("Invalid path. Restart script and enter a valid path")
            idc.Exit

        for item in os.listdir(dir_path):
            filename = os.path.join(dir_path, item)

            if not os.path.isfile(filename):
                continue
            
            if not filename.endswith('.txt'):
                continue

            with open(filename, 'rb') as fh:
                symbols = self.fixdata(fh)
                self.createenum(symbols)
    
    def fix_names(self):
        """ 
            Fix the table of imports and map enums to apis.
        """
        start_addr  = idc.AskAddr(idc.here(), "Enter table start address")

        ## check if address is within the base address and maximum address
        if (start_addr < idc.MinEA()) or (start_addr > idc.MaxEA()):
            idc.Warning("You have entered an invalid start address")
            idc.Exit

        self.start_addr = start_addr    
        current_addr = self.start_addr

        #Current size of PoisonIvy IAT
        end_addr = current_addr + 568

        # Walk the table 8 bytes at a time
        while current_addr <= end_addr:

            idc.MakeQword(current_addr)
            print "DEBUG: Current address - 0x%08x" % current_addr
            addr = idc.Qword(current_addr)
            print "DEBUG: address - 0x%08x" % addr
            if addr == -1:
                print "[!] Skipping address 0x%08x - 0x%08x" % (current_addr, addr)
                current_addr += 8
                continue

            # Make the current address an offset
            idc.OpOff(current_addr,0,0)
            # We need to undefine the bytes incase IDA autoanalysis had converted an incorrect byte
            idc.MakeUnkn(addr, 1)
            # Create code at this address 
            idc.MakeCode(addr)
            # Create function at the same address
            idc.MakeFunction(addr, addr+16)
            # Read the second operand at the address which should be the negative API address value
            imp_addr = idc.GetOperandValue(addr, 1)

            if imp_addr == -1:
                print "[!] Couldn't get operand at address - 0x%08x" % addr
                current_addr +=8
                continue             

            # try:
            #     int_addr = int(imp_addr,16)
            # except ValueError as e:
            #     print "[!] Failed on: %s - %s\n" % (imp_addr, e)
            #     current_addr +=8 
            #     continue
            
            # if we know about this value then let's do the work
            if imp_addr in self.enums.keys():
                enum_id = self.enums[imp_addr]
                # Convert operand to enum 
                idc.OpEnumEx(addr, 1, enum_id,0)
                const_id = idc.GetConstEx(enum_id, imp_addr, 0, -1)
                fn_name = "fn_"+idc.GetConstName(const_id)
                off_name = "ptr_"+idc.GetConstName(const_id)
                # Rename the function to the symbol name.
                # We append fn_ to the symbol for the function name
                # and ptr_ to the offset in the table.
                if not idc.MakeNameEx(addr, fn_name, idaapi.SN_NOWARN):
                    print "[!] Failed to rename function %s at 0x%08x\n" % (fn_name, addr)
                if not idc.MakeNameEx(current_addr, off_name, idaapi.SN_NOWARN):
                    print "[!] Failed to rename offset %s at 0x%08x\n" % (off_name,current_addr)

            current_addr += 8

        return 

pivy_idb = Pivy()
pivy_idb.make_enums()
pivy_idb.fix_names()
import sys
import os
import logging
from capstone import *
from capstone.x86 import *
import pefile

########
# Author: David Cannings @edeca
#   Date: November 2018
#
# Check a portable executable file and detect suspicious exports.  Currently
# this looks for a large amount of exports pointing to the same address.
#
# Anomalous entries (those with only 1 export) are printed for further
# analysis.  This suits the libcef based loader.
#
# Originally designed for use with loaders used by APT10 (libcef, Starburn 
# etc.).  Usage of this DLL planting technique with a "fake" DLL is not
# exclusive to APT10.
#
# Try this script with sample: d1adc4f3a766b1bc55e3508c380c6d3d.
########

def load_pe(filename):
    """
    Load a PE file.  Returns the pefile object or None.
    """
    # TODO: Exception handling (return None)
    dirs = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    try:
        pe = pefile.PE(filename, fast_load=True)
        pe.parse_data_directories(directories=dirs)
    except:
        return None

    return pe

def has_exports(pe):
    """
    Returns True if the PE exports anything, or False otherwise.
    """
    return hasattr(pe, 'DIRECTORY_ENTRY_EXPORT')

def extract_counts(pe):
    """
    Extract the number of exports that point to each address.  Returns
    a dictionary like dict[address] = count.
    """
    export_counts = {}

    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if e.name:
            name = e.name.decode('ascii')
        else:
            name = "ord_{:08x}".format(e.address)

        try:
            export_counts[e.address]['count'] += 1
            export_counts[e.address]['names'].append(name)
        except KeyError:
            data = { 'count': 1, 'names': [ name ], 'suspicious': False }
            export_counts[e.address] = data

    return export_counts

def is_suspicious(pe, export_counts):
    """
    Check whether this set of exports is suspicious.  Uses advanced
    machine learning algorithms based on blockchain.
    """
    suspicious = False
    num_multiple = 0
    num_junk = 0
    code = None
    offset = 0

    # TODO: Janky code reuse.  PE can have more than one code section.
    #       Instead get the correct section based on the export.  However,
    #       this works for >99% of cases...
    for section in pe.sections:
        if section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']:
            # Get data
            code = pe.get_memory_mapped_image()[section.VirtualAddress:section.VirtualAddress+section.SizeOfRawData]

            # Could just use section.get_data() here, but safer to use
            # memory mapped image as relocations etc. can be applied
            code = section.get_data()

            # Get the base address for later adjustments
            offset = section.VirtualAddress

    for address,data in export_counts.items():
        # Check 1:
        #
        # Absolute count of exports pointing to the same VA, which
        # is possible but unusual.

        # TODO: This metric works well for libcef based loaders, needs
        #       to be checked against others.  Perhaps use a % of total
        #       exports?
        if data['count'] > 5:
            logging.debug("Export at {} has >5 entries pointing to it".format(address))
            num_multiple += data['count']
            data['suspicious'] = True

        # Check 2:
        #
        # Look for known sequences of junk code, e.g. the Starburn based loaders.

        # TODO: Check for 64-bit samples and amend if needed
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True

        disasm_offset = address - offset

        logging.debug("Disassembling {} from 0x{:08x}".format(data['names'], disasm_offset))

        mnems = []
        for i in md.disasm(code[disasm_offset:disasm_offset + 64], disasm_offset):
            logging.debug("0x%x:\t%s\t%s", i.address, i.mnemonic, i.op_str)
            mnems.append(i.mnemonic)

            if i.mnemonic == "ret":
                break

        if mnems == [ 'push', 'push', 'push', 'push', 'call', 'xor', 'ret' ]:
            logging.debug("Export at 0x{:08x} matches a known junk code signature".format(address))
            num_junk += 1
            data['suspicious'] = True

    if num_junk or num_multiple:
        logging.warning("Found {} exports that point to the same place and {} known junk exports".format(num_multiple, num_junk))
        return True

    return False

def main():
    logging.basicConfig(level=logging.INFO)

    filename = sys.argv[1]
    if not os.path.exists(filename):
        sys.exit(1)

    pe = load_pe(filename)
    if pe is None:
        logging.error("Could not open file as PE: {}".format(filename))
        sys.exit(1)

    logging.info("Loaded file {}".format(filename))

    if not has_exports(pe):
        logging.info("PE has no exports, skipping")
        sys.exit(0)

    export_counts = extract_counts(pe)
    if is_suspicious(pe, export_counts):
        logging.warning("Suspicious exports found in this PE file")
        for address,data in export_counts.items():
            if not data['suspicious']:
                va = pe.OPTIONAL_HEADER.ImageBase + address
                logging.warning("Examine {} at 0x{:08x}".format(data['names'][0], va))

if __name__ == "__main__":
    main()

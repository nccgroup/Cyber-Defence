########
# Author: Cedric Halbronn <cedric.halbronn@nccgroup.com>
# Date: July 2016
# 
# Retrieves obfuscated names in stage 2 from assembly files and update decompiled source code names
# It renames all the symbols associated with names containing §. 
# The algorithm is the following:
# - We parse all Assembly files (.pcode)
# - When a variable’s or function’s obfuscated name (i.e. containing a §) is detected, we save the
#   obfuscated name
# - When a name "..." is detected, we save the previously obfuscated name with the real name in a symbols
#   dictionary
# - Finally we replace all found symbols in the Action Script files (.as)
########

import os
import pprint
import re
import sys
import binascii

# helper
def beautiful_str(s):
    res = ""
    for c in s:
        if ord(c) >= 0x20 and ord(c) <= 0x7e:
            res += c
        else:
            res += "\\x%02x" % ord(c)
    return res

# pattern is the special character used in all obfuscated names
#
# funcToBeRenamed() and isName() parse something like:
#
# private final function <obfuscated_name>() : Boolean
# {
#  ...
#  name "<symbol>"
#
# and associate the <obfuscated_name> with <symbol>
def funcToBeRenamed(items, pattern="\xa7"):
    if len(items) > 0 and (items[0] == 'private' or items[0] == 'public'):
        items.pop(0)
    if len(items) > 0 and items[0] == 'final':
        items.pop(0)
    if len(items) > 0 and items[0] == 'static':
        items.pop(0)
    if len(items) > 0 and items[0] == 'function':
        items.pop(0)
    if len(items) > 0 and pattern in items[0]:
        obfuscated_name = items[0]
        if "(" in obfuscated_name:
            obfuscated_name = obfuscated_name.split("(")[0]
        return obfuscated_name
    return None

def isName(items):
    if len(items) == 2 and items[0] == "name" and \
        items[1][0] == '"' and items[1][-1] == '"':
        return (items[1][1:-1], True)
    return (None, False)

n_str = 0
n_obj = 0
n_arr = 0
n_class = 0
# helper
def type2name(type0):
    global n_str, n_obj, n_arr, n_class
    if type0 == "String;":
        n_str += 1
        return "m_myStr%02d" % n_str
    if type0 == "Object;":
        n_obj += 1
        return "m_myObj%02d" % n_obj
    if type0 == "ByteArray;":
        n_arr += 1
        return "m_myArray%02d" % n_arr
    if type0 == "Class;":
        n_class += 1
        return "m_myClass%02d" % n_class
    return None

# parse something like:
#
# private var <obfuscated_name>:String;
# associate the <obfuscated_name> with m_myStrXX
def varToBeRenamed(items, pattern="\xa7"):
    if len(items) > 0 and (items[0] == 'private' or items[0] == 'public'):
        items.pop(0)
    if len(items) > 0 and items[0] == 'var':
        name_type = items[1].split(":")
        if len(name_type) == 2 and pattern in name_type[0]:
            name = type2name(name_type[1])
            return name_type[0], name
    return None

symbols = {}

# parse the assembly

pcode_files = []
for (dirpath, dirnames, filenames) in os.walk("ByteCode_unmodified"):
    for f in filenames:
        if f.endswith(".pcode"):
            pcode_files.append(os.path.join(dirpath, f))

inFunc = None
for f in pcode_files:
    fd = open(f, "r")
    for l in fd:
        l_stripped = l.strip().rstrip()
        items = l_stripped.split()
        obfuscated_name = funcToBeRenamed(items)
        if obfuscated_name != None:
            inFunc = obfuscated_name
            #print "%s in %s" % (beautiful_str(inFunc), l_stripped)
            continue
        
        items = l_stripped.split()
        res = varToBeRenamed(items)
        if res != None:
            symbols[res[0]] = res[1]
            #print "%s -> %s" % (beautiful_str(res[0]), res[1])
            continue

        if inFunc != None:
            items = l_stripped.split()
            name, res = isName(items)
            if not res:
                continue
            symbols[inFunc] = name
            #print "%s -> %s" % (beautiful_str(inFunc), name)
            inFunc = None
            continue

print "Found %d symbols" % len(symbols)
pprint.pprint(symbols)
for k, v in symbols.items():
    print "%s, " % v,
sys.exit()

# update the Action Script

as_files = []
for (dirpath, dirnames, filenames) in os.walk("src_renamed_good_names"):
    for f in filenames:
        if f.endswith(".as"):
            as_files.append(os.path.join(dirpath, f))

for f in as_files:
    data = open(f, "rb").read()
    for inFunc, name in symbols.items():
        data = data.replace(inFunc, name)
        open(f, 'wb').write(data)
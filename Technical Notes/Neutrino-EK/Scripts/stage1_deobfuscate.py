########
# Author: Cedric Halbronn <cedric.halbronn@nccgroup.com>
# Date: July 2016
# 
# Removes unused assignments in stage 1 decompiled source code to make it more readable
# The algorithm is:
# - We do a first pass to save variables names that are NOT part of a simple assignment to integer 
#  (e.g.: _loc53_ ,_loc19_ , _loc48_ , etc. above).
# - We do a second pass to remove all simple assignments to integer if they are not in the previous list.
########

import sys, binascii, re 

# Check if the list of items corresponds to the following lines:
# "var _loc8_:int = 0;"
# "_loc17_ = 460107;"
def isAssign(items):
    if not items:
        return False, None
    if items[0] == 'var':
        items.pop(0)
    r = re.match("^_loc(.*)_:\*$", items[0])
    s = re.match("^_loc(.*)_$", items[0])
    t = re.match("^_loc(.*)_:int$", items[0])
    u = re.match("^_loc(.*)_:uint$", items[0])
    if not t and not s and not r and not u:
        return False, None
    if items[1] != '=':
        return False, None
    z = re.match("^([0-9]*)$", items[2].rstrip(";"))
    if not z:
        return False, None
    if r:
        loc = r.group(1)
    elif s:
        loc = s.group(1)
    elif t:
        loc = t.group(1)
    elif u:
        loc = u.group(1)
    return True, loc

# look for _locXX_ reused that are not assignement to constant
reused = set([])
f = open('owaugjojgtx.as', 'r')
for l in f:
    l_stripped = l.strip().rstrip()
    items = l_stripped.split()
    bAssign, loc = isAssign(items)
    if bAssign:
        continue
    locs = re.findall(r'_loc([0-9]*)_', l_stripped)
    if not locs:
        continue
    print "%s -> %s" % (str(items), locs)
    reused.update(locs)
f.close()

# look for _locXX_ that are assignement to constant
# if they are not modified anywhere else (see previous list), then we can comment them
#f_out = open('owaugjojgtx_commented.as', 'w')
f_out = open('owaugjojgtx_deobfuscated.as', 'w')
f = open('owaugjojgtx.as', 'r')
for l in f:
    bWrite = True
    l_stripped = l.strip().rstrip()
    items = l_stripped.split()
    bAssign, loc = isAssign(items)
    l_out = l
    if bAssign:
        print "%s -> %s, %s" % (str(items), bAssign, loc)
        if loc not in reused:
            # comment it
            #l_out = '//' + l
            bWrite = False
    if bWrite:
        f_out.write(l_out)
f.close()
f_out.close()
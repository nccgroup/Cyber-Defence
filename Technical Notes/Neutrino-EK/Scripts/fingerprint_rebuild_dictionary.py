########
# Author: Cedric Halbronn <cedric.halbronn@nccgroup.com>
# Date: July 2016
# 
# Replace function calls by the actual dictionnary being created to make it more readable
# 
# g[a] = J("name", d["name"], "type", d["type"], "loading", 0, "interactive", 0, "complete", 0);
# becomes after rebuilding the dictionary and indentation:
# g[a] = {
#  "name" : d["name"],
#  "type" : d["type"],
#  "loading" : 0,
#  "interactive" : 0,
#  "complete" : 0
# };
########

import sys, re, pprint

# J() calls manually extracted from the JavaScript code
codes = []
codes.append('''J("name", d["name"], "type", d["type"], "loading", 0, "interactive", 0, "complete", 0)''')
codes.append('''J("debug", false, "maxParallelCheck", 30, "frameName", "myFrame")''')
codes.append('''J("name", "VirtualBox Guest Additions", "res", "res://C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\DIFxAPI.dll/#24/123", "type", "vm")''')
codes.append('''J("name", "VMware Tools", "res", "res://C:\\Program Files\\VMware\\VMware Tools\\VMToolsHook.dll/#24/2", "type", "vm")''')
codes.append('''J("name", "Fiddler2", "res", "res://C:\\Program Files (x86)\\Fiddler2\\uninst.exe/#24/1", "type", "tool")''')
codes.append('''J("name", "Wireshark", "res", "res://C:\\Program Files (x86)\\Wireshark\\wireshark.exe/#24/1", "type", "tool")''')
codes.append('''J("name", "FFDec", "res", "res://C:\\Program Files (x86)\\FFDec\\Uninstall.exe/#24/1", "type", "tool")''')
codes.append('''J("name", "ESET NOD32 Antivirus", "res", "res://C:\\Program Files\\ESET\\ESET NOD32 Antivirus\\egui.exe/#24/1", "type", "av")''')
codes.append('''J("name", "Bitdefender 2016", "res", "res://C:\\Program Files\\Bitdefender Agent\\ProductAgentService.exe/#24/1", "type", "av")''')

codes_replaced = []
for code in codes:
    #calls_list = re.findall("J\(.*?\)", code) # not greedy, fails because of "(x86)"
    calls_list = re.findall("J\(.*\)", code)
    #pprint.pprint(calls_list)
    for s in calls_list:
        start = len("J(")
        args = s[start:-1].split(", ")
        #print args
        res = "{"
        for i in range(0, len(args), 2):
            res += "%s: %s, " % (args[i], args[i+1])
        res = res[:-2]
        res += "}"
        codes_replaced.append(res)

data = open("4_res_js_rc4_3_removed_unused_functions.js_", "rb").read()
for i in range(len(codes)):
    # Note the double `\\` so it is still valid after writing the result
    data = data.replace(codes[i].replace("\\", "\\\\"), codes_replaced[i].replace("\\", "\\\\"))
open("4_res_js_rc4_4_dictionary_rebuilt.js_", 'wb').write(data)
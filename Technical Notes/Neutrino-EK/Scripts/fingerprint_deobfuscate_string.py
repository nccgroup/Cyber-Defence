########
# Author: Cedric Halbronn <cedric.halbronn@nccgroup.com>
# Date: July 2016
# 
# Replaces decrypted strings in JavaScript fingerprinting component
# It replaces instances of the v array
########

# Below has been optained by running the following JavaScript code in Chrome 44.0.2403 console:
# var v = (I)("ikbao%daPor...", 1391848);
# function I(h, a){
#       ...
#       return m.join(b).split(i).join(g).split(e).join(q).split(c).join(n).split(g);
# }
# then printing the result:
# v
#
# Note we replaced each `\` by `\\\\` because we want `\\` to be stored in the JavaScript
v = ["debug", "maxParallelCheck", "frameName", "myFrame", "name", "VirtualBox Guest Additions", "res", "res://C:\\\\Program Files\\\\Oracle\\\\VirtualBox Guest Additions\\\\DIFxAPI.dll/#24/123", "type", "vm", "VMware Tools", "res://C:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\VMToolsHook.dll/#24/2", "Fiddler2", "res://C:\\\\Program Files (x86)\\\\Fiddler2\\\\uninst.exe/#24/1", "tool", "Wireshark", "res://C:\\\\Program Files (x86)\\\\Wireshark\\\\wireshark.exe/#24/1", "FFDec", "res://C:\\\\Program Files (x86)\\\\FFDec\\\\Uninstall.exe/#24/1", "ESET NOD32 Antivirus", "res://C:\\\\Program Files\\\\ESET\\\\ESET NOD32 Antivirus\\\\egui.exe/#24/1", "av", "Bitdefender 2016", "res://C:\\\\Program Files\\\\Bitdefender Agent\\\\ProductAgentService.exe/#24/1", "length", "[START] checking process ...", "Software for checking: ", "getTime", "successCallback", "failCallback", "pop", "=== Checking element: ", ", on iframe: ", " ===", "loading", "interactive", "complete", "getElementById", "src", "setAttribute", "readyState", "onCheckState: iframe: ", ", state: ", ", software: ", "onLoad: iframe loaded: ", "[FOUND]: ", ":", "push", "[NOT FOUND]: ", "[FINISH] checking process", "Calling successCallback", "Calling failCallback", " ", "log", "creating iframe: ", "iframe", "createElement", "id", "width", "style", "1px", "height", "readystatechange", "load", "appendChild", "body", "deleting iframe: ", "removeChild", "parentNode", "addEventListener", "attachEvent", "on", "removeEventListener", "detachEvent", "object", "getElementsByTagName", "onSuccess", "function", "embed", "onFailed"]
infile = '4_res_js_rc4_1_indented.js_'
outfile = '4_res_js_rc4_2_v_replaced.js_'
data = open(infile, 'rb').read()
for i in range(len(v)):
    data = data.replace("v[%s]" % i, '"%s"' % v[i])
open(outfile, 'wb').write(data)
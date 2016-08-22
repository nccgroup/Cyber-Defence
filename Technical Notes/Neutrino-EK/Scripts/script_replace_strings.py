########
# Author: Cedric Halbronn <cedric.halbronn@nccgroup.com>
# Date: July 2016
# 
# Replaces decrypted strings in VB script
########

# List below obtained executing: 
# C:\>cscript /E:jscript deobfuscate_strings.vbs
u =  [
"WinHTTP",
"Request.5.1",
"GET",
"Scripting.FileSystemObject",
"WScript.Shell",
"ADODB.Stream",
"ero",
".exe",
"GetTempName",
"charCodeAt",
"iso-8859-1",
"",
"indexOf",
".dll",
"ScriptFullName",
"join",
"run",
" /c ",
" /s ",
]

infile = 'script_1_indented.vbs_'
outfile = 'script_2_u_replaced.vbs_'
data = open(infile, 'rb').read()
for i in range(len(u)):
    data = data.replace("u(%s)" % i, '"%s"' % u[i])
open(outfile, 'wb').write(data)
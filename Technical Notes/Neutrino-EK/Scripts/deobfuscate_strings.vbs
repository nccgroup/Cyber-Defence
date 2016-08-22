////////
// Author: Cedric Halbronn <cedric.halbronn@nccgroup.com>
// Date: July 2016
// 
// Retrieves obfuscated strings in VB script
////////

// used to generate the list of strings
var i3 = "WinHTTPZRequest.5.1ZGETZScripting.FileSystemObjectZWScript.ShellZADODB.StreamZeroZ.ex";
var u = function (i) {
	return i3["\x73p\x6ci\x74"]("\x5a")[i]
};
i3 += "eZGetTe" + "mpNameZcharCodeAtZiso-8859-1ZZindexO" + "fZ.d" + "llZScr" + "iptF" + "ullNa" + "meZjo" + "inZr" + "unZ" + " /c Z /s ";
var i;
for (i = 0; i<=18; i++)
    WScript.Echo("\"" + u(i) + "\",")
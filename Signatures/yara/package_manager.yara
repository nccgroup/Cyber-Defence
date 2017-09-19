rule exploit_ole_package_manager {
  meta:
    author = "David Cannings"
    description = "Office Package Manager, may load unsafe content including scripts"
    ref = "http://quicksand.io/"

  strings:
    // Parsers will open files without the full 'rtf'
    $header_rtf = "{\\rt" nocase
    $header_office = { D0 CF 11 E0 }
    $header_xml = "<?xml version=" nocase wide ascii

    // Marks of embedded data (reduce FPs)
    // RTF format
    $embedded_object   = "\\object" nocase
    $embedded_objdata  = "\\objdata" nocase
    $embedded_ocx      = "\\objocx" nocase
    $embedded_objclass = "\\objclass" nocase
    $embedded_oleclass = "\\oleclsid" nocase
    
    // XML Office documents
    $embedded_axocx      = "<ax:ocx"  nocase wide ascii
    $embedded_axclassid  = "ax:classid"  nocase wide ascii

    // OLE format
    $embedded_root_entry = "Root Entry" wide
    $embedded_comp_obj   = "Comp Obj" wide
    $embedded_obj_info   = "Obj Info" wide
    $embedded_ole10      = "Ole10Native" wide
 
    $data0 = "0003000C-0000-0000-c000-000000000046" nocase wide ascii
    $data1 = { 0C00030000000000c000000000000046 }
    
  condition:
    // Mandatory header plus sign of embedding, then any of the others
    for any of ($header*) : ( @ == 0 ) and 1 of ($embedded*) 
        and (1 of ($data*))
}

rule exploit_ole_package_manager_poss {
  meta:
    author = "David Cannings"
    description = "Office Package Manager, needs triage, these clsids are all surrogates"

  strings:
    // Parsers will open files without the full 'rtf'
    $header_rtf = "{\\rt" nocase
    $header_office = { D0 CF 11 E0 }
    $header_xml = "<?xml version=" nocase wide ascii

    // Marks of embedded data (reduce FPs)
    // RTF format
    $embedded_object   = "\\object" nocase
    $embedded_objdata  = "\\objdata" nocase
    $embedded_ocx      = "\\objocx" nocase
    $embedded_objclass = "\\objclass" nocase
    $embedded_oleclass = "\\oleclsid" nocase
    
    // XML Office documents
    $embedded_axocx      = "<ax:ocx"  nocase wide ascii
    $embedded_axclassid  = "ax:classid"  nocase wide ascii

    // OLE format
    $embedded_root_entry = "Root Entry" wide
    $embedded_comp_obj   = "Comp Obj" wide
    $embedded_obj_info   = "Obj Info" wide
    $embedded_ole10      = "Ole10Native" wide

    $data0 = "00020C01-0000-0000-C000-000000000046" nocase wide ascii
    $data1 = { 010C020000000000C000000000000046 }
      
    $data2 = "00020C01-0000-0000-C000-000000000046" nocase wide ascii
    $data3 = { 010C020000000000C000000000000046 }
    
    $data4 = "00022601-0000-0000-C000-000000000046" nocase wide ascii
    $data5 = { 0126020000000000C000000000000046 }
    
    $data6 = "00022602-0000-0000-C000-000000000046" nocase wide ascii
    $data7 = { 0226020000000000C000000000000046 }
    
    $data8 = "00022603-0000-0000-C000-000000000046" nocase wide ascii
    $data9 = { 0326020000000000C000000000000046 }
    
      
    $data10 = "0003000D-0000-0000-C000-000000000046" nocase wide ascii
    $data11 = { 0D00030000000000C000000000000046 }
    
    $data12 = "0003000E-0000-0000-C000-000000000046" nocase wide ascii
    $data13 = { 0E00030000000000C000000000000046 }
    
      
    $data14 = "F20DA720-C02F-11CE-927B-0800095AE340" nocase wide ascii
    $data15 = { 20A70DF22FC0CE11927B0800095AE340 }
    

  condition:
    // Mandatory header plus sign of embedding, then any of the others
    for any of ($header*) : ( @ == 0 ) and 1 of ($embedded*) 
        and (1 of ($data*))
}

rule exploit_Office_ActiveX_Packager {
  meta:
    author = "David Cannings"
    description = "Generic rule to detect RTF or Office files using packager.dll ActiveX control"
    ref = "https://blogs.mcafee.com/mcafee-labs/dropping-files-temp-folder-raises-security-concerns/"
    md5 = "d1bb6c0a522a689a880636e4d9b76600"
    
  strings:
    $header_rtf = "{\\rt"
    $header_office = { D0 CF 11 E0 }
    
    $suspicious01 = "\\objemb"
    $suspicious02 = "\\*\\objclass Package"
    
    // "Package" as embedded in objdata stream
    $suspicious03 = "5061636b61676500"
    
  condition:
    1 of ($header*) and 2 of ($suspicious*)    
}
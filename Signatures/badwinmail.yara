rule exploit_Office_Badwinmail {
  meta:
    author = "David Cannings"
    description = "Specific rule to detect files containing SWF objects, e.g. Badwinmail"
    ref = "https://cansecwest.com/slides/2016/CSW2016_Li-Xu_BadWinmail_and_EmailSecurityOutlook_final.pdf"
    
  strings:
    $header_tnef = { 78 9F 3E 22 }
    $header_docf = { D0 CF 11 E0 }

    // Reduce FPs on other DOCF documents by requiring Outlook specific properties
    // Could be improved by taking further items from MS-OXMSG specs.
    $msg_recip = "__recip_version1.0" wide
    $msg_attach = "__attach_version1.0" wide
    $msg_props = "__properties_version" wide
    
    // TODO: Is there any requirement to signature RFC822 emails?
    
    // SWF class identifiers, as embedded in the document
    $embedded_clsid_hex = "D27CDB6E-AE6D-11cf-96B8-444553540000" nocase wide ascii
    $embedded_class = "objclass ShockwaveFlash."
    $embedded_clsid = { 6e db 7c d2 6d ae cf 11 96 b8 44 45 53 54 00 00 }

  condition:
    (
     $header_tnef at 0 or 
     (
      $header_docf at 0 and
      2 of ($msg_*)
     )
    ) and 
    1 of ($embedded*)
}
# Microsoft's
we originally generated these on Saturday March 6th, 2021.

as of late Sunday (7th) / early Monday (8th) UTC Microsoft released 
their own master 
set:
* https://github.com/microsoft/CSS-Exchange/tree/main/Security/Baselines

as of early Tuesday (9th) UTC their our script:
* 
https://github.com/microsoft/CSS-Exchange/blob/main/Security/CompareExchangeHashes.ps1

We recommend you use these if you can. Otherwise our repo will stay.

# Generation

Generated from the installation archives/packages using:
* `find /[PATHTOEXCHANGEINSTALLROOT]/Setup/ServerRoles/ -type f -exec md5sum {} \; > MD5`
* `find /[PATHTOEXCHANGEINSTALLROOT]/Setup/ServerRoles/ -type f -exec sha1sum {} \; > SHA1`
* `find /[PATHTOEXCHANGEINSTALLROOT]/Setup/ServerRoles/ -type f -exec sha256sum {} \; > SHA2`

# Use

We've also included md5check.bat which is able to use the MD5 hash sets to identify unexpected files.

# Incident Response

To engage with our CIRT due to a breach please contact cirt@nccgroup.com

NCC Group operates a global incident response division. We have incident response teams in the USA, Canada, United Kingdom, Netherlands, 
Germany, Denmark, Spain, Singapore, Australia and Japan.

To learn more see: https://www.nccgroup.com/us/protection-detection-and-response/incident-response/


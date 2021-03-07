# Generation

Generated from the installations of all files using:
* `find /[PATHTOEXCHANGEINSTALLROOT]/Setup/ServerRoles/ -type f -exec md5sum {} \; > MD5`
* `find /[PATHTOEXCHANGEINSTALLROOT]/Setup/ServerRoles/ -type f -exec sha1sum {} \; > SHA1`
* `find /[PATHTOEXCHANGEINSTALLROOT]/Setup/ServerRoles/ -type f -exec sha256sum {} \; > SHA2`

# Use

We've also included md5check.bat which is able to use the MD5 hash sets to identify unexpected files.

# Incident Response

To engage with our CIRT team due to a breach please contact cirt@nccgroup.com

NCC Group operates a global incident response division. We have incident response teams in the USA, Canada, United Kingdom, Netherlands, 
Germany, Denmark, Spain, Singapore, Australia and Japan.

To learn more see: https://www.nccgroup.com/us/protection-detection-and-response/incident-response/


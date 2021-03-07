Generated from the installations of all files, generated using:
* find /[PATHTOEXCHANGEINSTALLROOT]/Setup/ServerRoles/ -type f -exec md5sum {} \; > MD5
* find /[PATHTOEXCHANGEINSTALLROOT]/Setup/ServerRoles/ -type f -exec sha1sum {} \; > SHA1
* find /[PATHTOEXCHANGEINSTALLROOT]/Setup/ServerRoles/ -type f -exec sha256sum {} \; > SHA2

We've also included md5check.bat which is able to use the MD5 hash sets to identify unexpected files.

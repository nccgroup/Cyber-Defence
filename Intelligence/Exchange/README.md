Generated from the installations of all files, generated using:
* find /[PATHTOEXCHANGEINSTALLROOT]/Setup/ServerRoles/ -type f -exec md5sum {} \; > MD5
* find /[PATHTOEXCHANGEINSTALLROOT]/Setup/ServerRoles/ -type f -exec sha1sum {} \; > SHA1
* find /[PATHTOEXCHANGEINSTALLROOT]/Setup/ServerRoles/ -type f -exec sha256sum {} \; > SHA2


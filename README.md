# AutoPwner

School project on last year of Master graduation, it consists as an automatic
scanning program to detect and exploit vulnerable services.

## Objectives

1. Network discovery [Must-have]
   * Host, service and version discovery
2. Vulnerabilities finding [Must-have]
   * Looking for exploits with `exploitdb/searchsploit` tool
   * Gather passwords and hashes, try hash cracking
3. Exploitation [Bonus]
   * Attempt to get control over network using previously found vulnerabilities
4. Lateral propagation [Bonus]
   * Use gathered data from exploit to attempt lateral movement
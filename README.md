# simple-LDAP-dump-script
A Python3.6+ script for dumping LDAP entries. Based on [Hacktricks' tutorial](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap) and modified to support authentication and pass the hash.

It produces extremely lengthy and difficult to read outputs. I was using this script before I realised [dirkjanm's ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) also supoorts passing the hash (I was too lazy to read its README so I thought it doesn't). Now I just use that wonderful tool instead of this script.

Whelp, uploading this to GitHub for archival purposes nonetheless.

# Requirements

- ldap3: `pip3 install ldap3`

# Usage

```
$ python3 ldap_dump.py -h
usage: ldap_dump.py [-h] [-u USERNAME] [-p PASSWORD] [-H HASH] [-s] ip_addr port_num

Script for dumping LDAP entries. Based on Hacktricks (https://book.hacktricks.xyz/network-
services-pentesting/pentesting-ldap). Modified to support anonymous login, plaintext credential
login, and NTLM pass-the-hash authentication. If no credential were provided, uses anonymous
login by default

positional arguments:
  ip_addr               LDAP server IP address
  port_num              LDAP server port number

options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Username for authentication
  -p PASSWORD, --password PASSWORD
                        Password for authentication
  -H HASH, --hash HASH  NTLM hashes for authentication, must be in LM:NT format
  -s, --secure          Enable SSL. Off by default.
```

## Anonymous Query
`python3 ldap_dump.py 127.0.0.1 389`

## Plaintext Credential Authentication
`python3 ldap_dump.py -u test -p 'Testing123!' 127.0.0.1 389`

## NTLM Pass the Hash Authentication
`python3 ldap_dump.py -u domain.local\\test -H 12345:54321 127.0.0.1 389`

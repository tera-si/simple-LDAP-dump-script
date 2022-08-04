#!/usr/bin/env python3

import ldap3
import argparse


def print_banner():
    separator = "#" * 80
    banner_text = "# LDAP dump script v1.0" + " " * 56 + "#\n"
    banner_text += "# Based on Hacktricks" + " " * 58 + "#\n"
    banner_text += "# https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap" + " " * 6 + "#\n"
    banner_text += "# Modified by terasi" + " " * 59 + "#\n"
    banner_text += "# https://github.com/tera-si" + " " * 51 + "#"

    print(separator)
    print(banner_text)
    print(separator + "\n")


def anonymous_connect(server):
    try:
        connection = ldap3.Connection(server)
        status = connection.bind()

        if not status:
            print("[!] Unable to connect to LDAP server anonymously")
            exit()
        else:
            print("[*] Anonymous connection established")
            return connection

    except Exception as e:
        print("[!] Error when connecting to LDAP server:")
        print(e)
        exit()


def simple_auth_connection(server, username, password):
    try:
        connection = ldap3.Connection(server, user=username, password=password)
        status = connection.bind()

        if not status:
            print(f"[!] Unable to connect to LDAP server using {username}:{password}")
            exit()
        else:
            print(f"[*] Authenticated connection established using {username}:{password}")
            return connection

    except Exception as e:
        print("[!] Error when authenticating/connecting to LDAP server:")
        print(e)
        exit()


def pth_auth_connection(server, username, ntlm_hash):
    try:
        connection = ldap3.Connection(server, user=username, password=ntlm_hash, authentication=ldap3.NTLM)
        status = connection.bind()

        if not status:
            print(f"[!] Unable to connect to LDAP server using {username}:{ntlm_hash}")
            exit()
        else:
            print(f"[*] Pass-the-hash authenticated connection established using {username}:{ntlm_hash}")
            return connection

    except Exception as e:
        print("[!] Error when authenticating/connecting to LDAP server:")
        print(e)
        exit()


def enum_basic_info(server):
    try:
        status = server.info

        if not status:
            print("[!] No data were received")
            exit()
        else:
            print(status)
            return status

    except Exception as e:
        print("[!] Error when enumerating basic server info:")
        print(e)
        exit()


def extract_naming_context(info):
    reference = "defaultNamingContext:"
    info = str(info)

    loc_start = info.find(reference)
    if loc_start == -1:
        print("[!] Naming context not found")
        print("[!] Aborting...")
        exit()
    else:
        loc_start = loc_start + len(reference)

    loc_end = info.find("currentTime:")
    return info[loc_start:loc_end].strip()


def dump_entries(connection, name_context):
    try:
        status = connection.search(search_base=name_context, search_filter="(&(objectClass=*))", search_scope="SUBTREE", attributes="*")

        if not status:
            print("[!] No data were received")
            exit()
        else:
            return connection.entries
    except Exception as e:
        print("[!] Error when dumping LDAP")
        print(e)
        exit()


def main():
    description = """Script for dumping LDAP entries.
    Based on Hacktricks
    (https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap).
    Modified to support anonymous login, plaintext credential login, and NTLM pass-the-hash
    authentication.
    If no credential were provided, uses anonymous login by default"""

    separator = "=" * 80
    args_parser = argparse.ArgumentParser(description=description)
    args_parser.add_argument("ip_addr", help="LDAP server IP address")
    args_parser.add_argument("port_num", help="LDAP server port number")
    args_parser.add_argument("-u", "--username", help="Username for authentication")
    args_parser.add_argument("-p", "--password", help="Password for authentication")
    args_parser.add_argument("-H", "--hash", help="NTLM hashes for authentication, must be in LM:NT format")
    args_parser.add_argument("-s", "--secure", help="Enable SSL. Off by default.", action="store_true")

    args = args_parser.parse_args()
    ip_addr = args.ip_addr
    port_num = args.port_num
    username = args.username
    password = args.password
    ntlm_hash = args.hash
    secure_switch = args.secure

    server = ldap3.Server(ip_addr, get_info=ldap3.ALL, port=int(port_num), use_ssl=secure_switch)
    connection = None

    print_banner()

    if password and ntlm_hash:
        print("[!] Both password and hashes are provided")
        print("[!] Please only use either one of them at a time")
        print("[!] Aborting...")
        exit()

    print("[*] Testing server connection and authentication")
    print(separator)

    if not username:
        if not password and not ntlm_hash:
            print("[*] Attempting anonymous connection")
            connection = anonymous_connect(server)
        else:
            print("[!] No username provided")
            print("[!] Aborting...")
            exit()
    elif password:
        print(f"[*] Attempting authentication with {username}:{password}")
        connection = simple_auth_connection(server, username, password)
    elif ntlm_hash:
        print(f"[*] Attempting pass-the-hash authentication with {username}:{ntlm_hash}")
        connection = pth_auth_connection(server, username, ntlm_hash)

    print(separator)
    print("[*] Enumerating basic domain info")
    print(separator)
    info = enum_basic_info(server)

    print(separator)
    print("[*] Extracting domain naming context:")
    print(separator)
    name_context = extract_naming_context(info)
    print(f"Found: {name_context}")

    print(separator)
    print("[*] Dumping LDAP")
    print(separator)
    entries = dump_entries(connection, name_context)
    print(entries)

if __name__ == "__main__":
    main()

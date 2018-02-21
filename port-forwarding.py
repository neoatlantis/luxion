#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TCP Port Forwarding via Socks5 Socket
# Original Author : WangYihang <wangyihanger@gmail.com> (for port forwarding)
#                   (As gist: <https://gist.github.com/WangYihang/e7d36b744557e4673d2157499f6c6b5e>)
# Changes         : NeoAtlantis <aurichalka@gmail.com> 
#                   (adapted to socks5, use argparse for CLI invokation, etc.)

import argparse
import re
import socks
import socket
import multiprocessing 
import sys

def proxy_socket(proxy_type, proxy_addr, *args):
    s = socks.socksocket(*args)
    s.set_proxy(proxy_type, proxy_addr[0], proxy_addr[1])
    return s


def transfer(src, dst, direction):
    src_name = src.getsockname()
    src_address = src_name[0]
    src_port = src_name[1]
    dst_name = dst.getsockname()
    dst_address = dst_name[0]
    dst_port = dst_name[1]
    while True:
        buffer = src.recv(0x400)
        if len(buffer) == 0:
            print "[-] No data received! Breaking..."
            break
        dst.send(buffer)
    print "[+] Closing connecions! [%s:%d]" % (src_address, src_port)
    #src.shutdown(socket.SHUT_RDWR)
    src.close()
    print "[+] Closing connecions! [%s:%d]" % (dst_address, dst_port)
    #dst.shutdown(socket.SHUT_RDWR)
    dst.close()


def server(src_address, dst_address, proxy_config, max_connection):
    if proxy_config:
        proxy_type, proxy_addr = proxy_config
        get_remote_socket = lambda: proxy_socket(
            proxy_type, proxy_addr, socket.AF_INET, socket.SOCK_STREAM)
    else:
        get_remote_socket = lambda: socket.socket(
            socket.AF_INET, socket.SOCK_STREAM)
        
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(src_address)
    server_socket.listen(max_connection)
    print '[+] Server started [%s:%d] -> [%s:%d]' % (src_address + dst_address)
    while True:
        local_socket, local_address = server_socket.accept()
        print '[+] Detect connection from [%s:%s]' % local_address
        print "[+] Trying to connect the REMOTE server [%s:%d]" % dst_address
        remote_socket = get_remote_socket()
        remote_socket.connect(dst_address)
        print "[+] Tunnel connected! Tranfering data..."
        s = multiprocessing.Process(target=transfer, args=(
            remote_socket, local_socket, False))
        r = multiprocessing.Process(target=transfer, args=(
            local_socket, remote_socket, True))
        s.start()
        r.start()
    print "[+] Releasing resources..."
    remote_socket.shutdown(socket.SHUT_RDWR)
    remote_socket.close()
    local_socket.shutdown(socket.SHUT_RDWR)
    local_socket.close()
    print "[+] Closing server..."
    server_socket.shutdown(socket.SHUT_RDWR)
    server_socket.close()
    print "[+] Server shuted down!"


def parse_addr(string, default_port=1080):
    parsed = re.match("([0-9a-zA-Z\\.]+)(:([0-9]{,5})){0,1}", string)
    host, port = parsed.group(1), parsed.group(3) 
    if not port:
        port = default_port
    else:
        port = int(port)
        assert port > 1 and port <= 65535
    return (host, port)


def main():
    parser = argparse.ArgumentParser(description="""
        A tool for port forwarding over a SOCKS4/5 Proxy. Currently only simple
        SOCKS proxies without authentication are supported.
    """)

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--socks4", "-s4", help="Use a SOCKS4 proxy.")
    group.add_argument("--socks5", "-s5", help="Use a SOCKS5 proxy.")

    parser.add_argument(
        "src_address",
        help="Source address, given by host:port, e.g.: 127.0.0.1:1080")

    parser.add_argument(
        "dst_address",
        help="Destination address, given by host:port, e.g.: 1.2.3.4:22")

    args = parser.parse_args()

    src_address = parse_addr(args.src_address)
    dst_address = parse_addr(args.dst_address, default_port=src_address[1])
    proxy_config = None
    if args.socks4:
        proxy_config = socks.SOCKS4, parse_addr(args.socks4)
    if args.socks5:
        proxy_config = socks.SOCKS5, parse_addr(args.socks5)

    MAX_CONNECTION = 0x10
    server(src_address, dst_address, proxy_config, MAX_CONNECTION)


if __name__ == "__main__":
    main()

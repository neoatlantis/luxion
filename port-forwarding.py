#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# TCP Port Forwarding via Socks5 Socket
# Original Author : WangYihang <wangyihanger@gmail.com> (for port forwarding)
#                   (As gist: <https://gist.github.com/WangYihang/e7d36b744557e4673d2157499f6c6b5e>)
# Changes         : NeoAtlantis <aurichalka@gmail.com> 
#                   (adapted to pySocks, argparse for CLI invokation, encryption, etc.)

import argparse
import hashlib
import hmac
import multiprocessing
import os
import select
import socket
import sys
import re

try:
    import socks
    from Crypto.Cipher import AES
except:
    print("Error: unsatisfied dependencies. Install Python packages with:")
    print(" sudo pip3 install pyCrypto pysocks")
    exit(1)

NONCE_LENGTH = 16 



def proxy_socket(proxy_type, proxy_addr, proxy_timeout, *args):
    s = socks.socksocket(*args)
    s.set_proxy(proxy_type, proxy_addr[0], proxy_addr[1])
    if proxy_timeout and proxy_timeout > 0:
        s.settimeout(proxy_timeout)
    return s

def clear_sockets(*sockets):
    for each in sockets:
        try:
            each.shutdown(socket.SHUT_RDWR)
        except:
            pass
        try:
            each.close()
        except:
            pass

#-----------------------------------------------------------------------------
# Encryption & Packet Streaming
# =============================
#
# 3 wrappers for sockets are provided:
#   ClientCryptoSocket, ServerCryptoSocket, NonCryptoSocket
#
# Wrappers modify a socket by adding encryption capability(the first 2
# variants), or just adapt a socket to same behaviour as a crypto socket(with
# NonCryptoSocket). This is necessary, since we need to raise Exception to tell
# parent loop a socket is not only emitting empty stream, but has got an
# EOF(ciphers will emit empty result awaiting for full packets be received
# anyway, so that's not sufficient to terminate a connection). By using
# NonCryptoSocket the behaviour of a normal socket.socket is adapted to this,
# too.
#
# By activating encryption, all data transmitted between 2 instances of our
# program are encrypted, but not authenticated. Authentications are done per
# chunk in plaintext stream before encryption, where a HMAC for each chunk is
# calculated and prefixed. To separate chunks inside a stream, we use LBE128
# encoding, where one encoded byte carrying 7 bits of original byte, thus
# reducing the bandwidth slightly by 1/8.
#
# Any attempt to tamper the ciphertext stream results in modification of
# plaintext stream, either making chunks cannot be reconstructed properly,
# or will change the content of each chunk, which, by most chances, renders
# a chunk unable to be decoded. Since a chunk is signed with HMAC, even if
# decoding successes, it will not survive afterwarding examination. Any error
# in this process will result an Exception, which terminates the connection
# immediately.
# 

class Base128Stream:

    def __init__(self):
        self.byteTo8bit = {
        }
        self.byteFrom8bit = {
            # incomplete paddings will be decoded to nothing
            "0": b"", 
            "00": b"", 
            "000": b"", 
            "0000": b"", 
            "00000": b"", 
            "000000": b"", 
            "0000000": b"", 
        }
        for i in range(0, 256):
            self.byteTo8bit[i] = bin(i)[2:].rjust(8, "0")
            self.byteFrom8bit[self.byteTo8bit[i]] = bytes([i])
        self.buffer = [] 

    def encode(self, data):
        assert type(data) == bytes
        binstr = "".join([self.byteTo8bit[each] for each in data])
        paddingZerosMod = len(binstr) % 7
        if paddingZerosMod > 0:
            binstr = "0000000"[paddingZerosMod:] + binstr
        binstr = binstr[::-1] # reverse binstr
        chunks = [binstr[start:start+7] for start in range(0, len(binstr), 7)]
        chunks = ["1%s" % each for each in chunks]
        chunks[-1] = "0%s" % chunks[-1][1:]
        return b"".join([self.byteFrom8bit[each] for each in chunks])

    def decode(self, data):
        assert type(data) == bytes
        self.buffer += [self.byteTo8bit[each] for each in data]
        results = []
        while True:
            result = self._clearBufferOnce()
            if result:
                results.append(result)
            else:
                break
        return results

    def _clearBufferOnce(self):
        end = -1
        for i in range(0, len(self.buffer)):
            if self.buffer[i][0] == "0":
                end = i
                break
        if end < 0: return None
        sliced = self.buffer[0:end+1]
        self.buffer = self.buffer[end+1:]
        binstr = "".join([each[1:] for each in sliced])
        chunks = [binstr[start:start+8] for start in range(0, len(binstr), 8)]
        chunks = [each[::-1] for each in chunks]
        chunks.reverse()
        data = b"".join([self.byteFrom8bit[each] for each in chunks])
        return data


def get_cipher(key, nonce):
    global NONCE_LENGTH
    if type(key) == str:
        key = key.encode("utf-8")
    assert type(key) == bytes
    assert type(nonce) == bytes and len(nonce) == NONCE_LENGTH
    key = hmac.new(key, nonce, hashlib.sha256).digest()
    cipher = AES.new(key=key, mode=AES.MODE_CFB, IV=nonce)
    return cipher


class AuthenticatedPacketStream:

    def __init__(self, key):
        if type(key) == str:
            key = key.encode('utf-8')
        assert type(key) == bytes
        key = hashlib.sha512(key).digest()
        self.__hmac = hmac.new(key, b"", hashlib.sha256)
        self.__hmac_len = 32
        self.__stream = Base128Stream()

    def __hash(self, data):
        h = self.__hmac.copy()
        h.update(data)
        return h.digest()
    
    def send(self, chunk):
        return self.__stream.encode(self.__hash(chunk) + chunk)

    def recv(self, chunk):
        raw_packets = self.__stream.decode(chunk)
        # verify
        result = []
        for raw_packet in raw_packets:
            sign = raw_packet[:self.__hmac_len]
            payload = raw_packet[self.__hmac_len:]
            assert self.__hash(payload) == sign
            result.append(payload)
        return result


class NonCryptoSocket:

    def __init__(self, socket):
        self.__orig_socket = socket

    def __getattr__(self, name):
        return getattr(self.__orig_socket, name)

    def recv(self, length):
        data = self.__orig_socket.recv(length)
        if not data: raise EOFError()
        return data


class ClientCryptoSocket:

    def __init__(self, orig_socket, key):
        self.__orig_socket = orig_socket
        self.__key = key
        self.__nonce = os.urandom(NONCE_LENGTH)
        self.__cipher = get_cipher(key, self.__nonce)
        self.__stream_processor = AuthenticatedPacketStream(key)
        self.__nonce_sent = False

    def __getattr__(self, name):
        return getattr(self.__orig_socket, name)

    def recv(self, length):
        recv_buffer = self.__orig_socket.recv(length)
        if not recv_buffer: raise EOFError()
        decrypted = self.__cipher.decrypt(recv_buffer)
        decoded = self.__stream_processor.recv(decrypted)
        return b"".join(decoded)

    def send(self, data):
        encoded = self.__stream_processor.send(data)
        sending = self.__cipher.encrypt(encoded)
        if not self.__nonce_sent:
            sending = self.__nonce + sending
            self.__nonce_sent = True
        return self.__orig_socket.send(sending)


class ServerCryptoSocket:

    def __init__(self, orig_socket, key):
        self.__orig_socket = orig_socket
        self.__key = key
        self.__cipher = None
        self.__stream_processor = AuthenticatedPacketStream(key)
        self.__send_plaintext_buffer = b""

    def __getattr__(self, name):
        return getattr(self.__orig_socket, name)

    def recv(self, length):
        if not self.__cipher:
            # cipher has to be initialized with a key and a nonce, the latter
            # sent from remote
            nonce_buffer = b""
            while len(nonce_buffer) < NONCE_LENGTH:
                recv = self.__orig_socket.recv(NONCE_LENGTH + length)
                if len(recv) == 0: raise EOFError()
                nonce_buffer += recv
            nonce = nonce_buffer[:NONCE_LENGTH]
            recv_buffer = nonce_buffer[NONCE_LENGTH:]
            self.__cipher = get_cipher(self.__key, nonce)
            print("[+] Incoming connection established!")
        else:
            recv_buffer = self.__orig_socket.recv(length)
            if not recv_buffer: raise EOFError()
        # cipher is initialized
        decrypted = self.__cipher.decrypt(recv_buffer)
        decoded = self.__stream_processor.recv(decrypted)
        return b"".join(decoded)

    def send(self, data):
        self.__send_plaintext_buffer += data
        if None == self.__cipher:
            return len(data)
        ret = self.__orig_socket.send(
            self.__cipher.encrypt(
                self.__stream_processor.send(self.__send_plaintext_buffer)
            )
        )
        self.__send_plaintext_buffer = b""
        return ret


#-----------------------------------------------------------------------------

def transfer(src, dst, timeout=300):
    src_name = src.getsockname()
    src_address = src_name[0]
    src_port = src_name[1]
    dst_name = dst.getsockname()
    dst_address = dst_name[0]
    dst_port = dst_name[1]
    interval = 60
    timeout_count = 0
    while True:
        readables, _, __ = select.select([src, dst], [], [], interval)
        if readables:
            timeout_count = 0
        else:
            timeout_count += interval
            if timeout_count > timeout: break
        try:
            for readable in readables:
                buffer = readable.recv(0x400)
                if readable == src:
                    dst.send(buffer)
                else:
                    src.send(buffer)
        except EOFError:
            break
        except Exception as e:
            print(e)
            break
    print("[+] Closing connecions! [%s:%d]" % (src_address, src_port))
    print("[+] Closing connecions! [%s:%d]" % (dst_address, dst_port))
    clear_sockets(src, dst)


def server(src_address, dst_address, proxy_config, max_connection, cs, cc):
    if proxy_config:
        proxy_type, proxy_addr, proxy_timeout = proxy_config
        get_remote_socket = lambda: proxy_socket(
            proxy_type, proxy_addr, proxy_timeout, socket.AF_INET,
            socket.SOCK_STREAM)
    else:
        get_remote_socket = lambda: socket.socket(
            socket.AF_INET, socket.SOCK_STREAM)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(src_address)
    server_socket.listen(max_connection)
    print('[+] Server started [%s:%d] -> [%s:%d]' % (src_address + dst_address))
    while True:
        local_socket, local_address = server_socket.accept()
        if cs:
            print('[+] Local port behaving as cipher end-point.')
            local_socket = ServerCryptoSocket(local_socket, cs)
        else:
            local_socket = NonCryptoSocket(local_socket)

        print('[+] Detect connection from [%s:%s]' % local_address)
        print("[+] Trying to connect the REMOTE server [%s:%d]" % dst_address)
        remote_socket = get_remote_socket()
        if cc:
            print('[+] Forwarding data from a cipher end-point.')
            remote_socket = ClientCryptoSocket(remote_socket, cc)
        else:
            remote_socket = NonCryptoSocket(remote_socket)

        try:
            remote_socket.connect(dst_address)
        except:
            print("[-] Error: cannot connect to proxy.")
            clear_sockets(remote_socket, local_socket)
            continue
            #exit(2)

        print("[+] Tunnel connected! Tranfering data...")
        s = multiprocessing.Process(target=transfer, args=(
            remote_socket, local_socket))
#        r = multiprocessing.Process(target=transfer, args=(
#            local_socket, remote_socket, True))
        s.start()
#        r.start()
    print("[+] Releasing resources...")
    remote_socket.shutdown(socket.SHUT_RDWR)
    remote_socket.close()
    local_socket.shutdown(socket.SHUT_RDWR)
    local_socket.close()
    print("[+] Closing server...")
    server_socket.shutdown(socket.SHUT_RDWR)
    server_socket.close()
    print("[+] Server shut down!")


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
    """, epilog="""
        On encryption: this program may pair 2 computers with one running with
        -cc/--crypto-client and another with -cs/--crypto-server option.
        Initiating this program with both options is also possible, in which
        way it will work as a relay decrypting and re-encrypting the data
        stream in transit using 2 different keys.
    """)

    proxy = parser.add_mutually_exclusive_group(required=False)
    proxy.add_argument("--socks4", "-s4", help="Use a SOCKS4 proxy.")
    proxy.add_argument("--socks5", "-s5", help="Use a SOCKS5 proxy.")
    proxy.add_argument("--http", help="Use a HTTP CONNECT proxy.")

    parser.add_argument(
        "--timeout", "-t",
        metavar="SECONDS",
        type=int,
        help="Set a timeout for proxy. Only useful if any proxy is set."
    )

    parser.add_argument(
        "--crypto-server", "-cs",
        metavar="PASSWORD",
        help="""Regard the incoming proxy stream as encrypted by this program
        under -cc/--crypto-client option. See below.""")

    parser.add_argument(
        "--crypto-client", "-cc",
        metavar="PASSWORD",
        help="""Proxied stream targeting the remote address will be encrypted,
        and can be decrypted only with another instance of this program started
        with -cs/--crypto-server option. See below.""")

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
        proxy_config = socks.SOCKS4, parse_addr(args.socks4), args.timeout
    if args.socks5:
        proxy_config = socks.SOCKS5, parse_addr(args.socks5), args.timeout
    if args.http:
        proxy_config = socks.HTTP, parse_addr(args.http), args.timeout

    MAX_CONNECTION = 0x10
    server(
        src_address, dst_address, proxy_config, MAX_CONNECTION,
        cs=args.crypto_server, cc=args.crypto_client)


if __name__ == "__main__":
    main()

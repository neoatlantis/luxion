#!/usr/bin/env python3

import hashlib
import base64
import hmac
import sys
import random
import math

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

        

import os
x = Base128Stream()

s = []
for i in range(0, 5000):
    l = random.randrange(10, 100)
    d = os.urandom(l)
    encoded = x.encode(d)
    decoded = x.decode(encoded)[0]
    if d != decoded:
        print(d.hex(), decoded.hex())
        exit()
    else:
        s.append(len(encoded) / len(d))
print("ok", sum(s) / len(s))
exit()






class AuthenticatedPacketStream:

    def __init__(self, key):
        self.__recv_buffer = b""
        if type(key) == str:
            key = key.encode('utf-8')
        assert type(key) == bytes
        key = hashlib.sha512(key).digest()
        self.__hmac = hmac.new(key, b"", hashlib.sha256)
        self.__hmac_len = 32

    def __hash(self, data):
        h = self.__hmac.copy()
        h.update(data)
        return h.digest()
    
    def send(self, chunk):
        return b"\n" + base64.b85encode(self.__hash(chunk) + chunk) + b"\n"

    def recv(self, chunk):
        self.__recv_buffer += chunk
        if b"\n" not in self.__recv_buffer:
            return []
        split = self.__recv_buffer.split(b"\n")
        raw_packets = [base64.b85decode(each) for each in split[:-1] if each]
        self.__recv_buffer = split[-1]
        # verify
        result = []
        for raw_packet in raw_packets:
            sign = raw_packet[:self.__hmac_len]
            payload = raw_packet[self.__hmac_len:]
            assert self.__hash(payload) == sign
            result.append(payload)
        return result


a = AuthenticatedPacketStream(b"akdfjaskdfja")
b = AuthenticatedPacketStream(b"akdfjaskdfja")

stream = b""
sendingPackets = [b"a", b"b", b"c"*10, b"hello"]
for s in sendingPackets:
    f = a.send(s)
    stream += f


randomSplit = []
while stream:
    length = random.randint(1, 10)
    randomSplit.append(stream[:length])
    stream = stream[length:]

for each in randomSplit:
    got = b.recv(each)
    if got:
        print(each, got)

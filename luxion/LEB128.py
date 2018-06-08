#!/usr/bin/env python3

class LEB128Stream:

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

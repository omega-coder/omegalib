#!/usr/bin/env python3

# coding : utf-8

import struct


class BTSnoop(object):
    MAGIC_NUMBER__ = b'\x62\x74\x73\x6e\x6f\x6f\x70\x00'

    def __init__(self, file_path):
        try:
            btsnoop_dump = open(file_path, 'rb')
            self.data = btsnoop_dump.read()
        except IOError, (errorno, strerror):
            print("I/O Error({}): {}".format(errorno, strerror))

        if !self.__check_signature():
            raise Exception

    # check file signature
    def __check_signature(self):
        return self.data[:8] == BTSnoop.MAGIC_NUMBER__

    # dump raw binary data
    def dump_raw(self):
        return self.data

    





if __name__ == "__main__":
    main()

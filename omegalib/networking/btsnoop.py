#!/usr/bin/env python3

# coding : utf-8

import struct


class BTSnoop(object):
    MAGIC_NUMBER__ = b'\x62\x74\x73\x6e\x6f\x6f\x70\x00'

    def __init__(self, file_path):
        self.__header_size = struct.calcsize('>II')
        self.__version = None
        self.__datalink_type = None
        try:
            btsnoop_dump = open(file_path, 'rb')
            self.data = btsnoop_dump.read()
        except IOError, (errorno, strerror):
            print("I/O Error({}): {}".format(errorno, strerror))

        if not self.__check_signature():
            raise Exception

    # check file signature
    def __check_signature(self):
        return self.data[:8] == BTSnoop.MAGIC_NUMBER__

    # dump raw binary data
    def dump_raw(self):
        return self.data

    def read_header(self):
        magic_number_len = len(MAGIC_NUMBER__)
        self.__version, self.__datalink_type = struct.unpack('>II', self.data[magic_number_len:magic_number_len+self.__header_size])
        if self.__version != 1:
            raise Exception('Version {} is not supported!'.format(self.__version))





if __name__ == "__main__":
    main()

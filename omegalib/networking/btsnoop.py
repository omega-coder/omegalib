#!/usr/bin/env python3

# coding : utf-8

import struct


class BTSnoop(object):
    MAGIC_NUMBER__ = b'\x62\x74\x73\x6e\x6f\x6f\x70\x00'

    BTSNOOP_FLAGS =  {
        0: ("host", "controller", "data"),
        1: ("controller", "host", "data"),
        2: ("host", "controller", "command"),
        3: ("controller", "host", "event")
    }
    __header_size = struct.calcsize('>II')


    def __init__(self, file_path):
        self.__version = None
        self.__datalink_type = None
        try:
            btsnoop_dump = open(file_path, 'rb')
            self.data = btsnoop_dump.read()
        except IOError, (errorno, strerror):
            print("I/O Error({}): {}".format(errorno, strerror))

        if not self.__check_signature():
            raise Exception
        try:
            self.__parse_header()
        except Exception as e:
            print(e)

    # check file signature
    def __check_signature(self):
        return self.data[:8] == BTSnoop.MAGIC_NUMBER__

    # dump raw binary data
    def dump_raw(self):
        return self.data

    def __parse_header(self):
        magic_number_len = len(MAGIC_NUMBER__)
        self.__version, self.__datalink_type = struct.unpack('>II', self.data[magic_number_len:magic_number_len+__header_size])
        if self.__version != 1:
            raise Exception('Version {} is not supported!'.format(self.__version))
        if self.__datalink_type != 0x3ea:
            raise Exception('Only H4 Datalink type is supported!')






if __name__ == "__main__":
    main()

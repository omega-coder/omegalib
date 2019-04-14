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
    __packet_rec_size = struct.calcsize('>IIIIq')

    def __init__(self, file_path):
        self.__version = None
        self.__datalink_type = None
        self.__last_seek = 0
        try:
            btsnoop_dump = open(file_path, 'rb')
            self.data = btsnoop_dump.read()
        except IOError (errorno, strerror):
            print("I/O Error({}): {}".format(errorno, strerror))

    def parse(self):
        try:
            self.__check_signature()
            self.__parse_header()
        except Exception as e:
            print(e)

        return map(lambda rec: (rec[0], rec[2], rec[3], rec[5], rec[6]), self.__parse_packet_rec())

    # check file signature
    def __check_signature(self):
        if not self.data[:8] == BTSnoop.MAGIC_NUMBER__:
            raise Exception("Could not check signature!!")

    # dump raw binary data
    def dump_raw(self):
        return self.data

    def __parse_header(self):
        magic_number_len = len(BTSnoop.MAGIC_NUMBER__)
        self.__version, self.__datalink_type = struct.unpack('>II', self.data[magic_number_len:magic_number_len+BTSnoop.__header_size])
        if self.__version != 1:
            raise Exception('Version {} is not supported!'.format(self.__version))
        if self.__datalink_type != 0x3ea:
            raise Exception('Only H4 Datalink type is supported!')

        self.__last_seek = magic_number_len + BTSnoop.__header_size



    def __parse_packet_rec(self):
        """
            --------------------------
            | original length        |
            | 4 bytes
            --------------------------
            | included length        |
            | 4 bytes
            --------------------------
            | packet flags           |
            | 4 bytes
            --------------------------
            | cumulative drops       |
            | 4 bytes
            --------------------------
            | timestamp microseconds |
            | 8 bytes
            --------------------------
            | packet data            |
            --------------------------
        """

        SEQ_N = 1
        while True:
            try:
                original_length, inc_length, flags, drops, ts_64 = struct.unpack('>IIIIq', self.data[self.__last_seek:self.__last_seek+BTSnoop.__packet_rec_size])
                assert original_length == inc_length
                data_start_index = self.__last_seek + BTSnoop.__packet_rec_size
                self.__last_seek += (BTSnoop.__packet_rec_size + inc_length)

                pkt_data = self.data[data_start_index:self.__last_seek]

                assert len(pkt_data) == inc_length

                yield (SEQ_N, original_length, inc_length, flags, drops, ts_64, pkt_data)
                SEQ_N += 1
            except Exception as e:
                break



if __name__ == "__main__":
    BTSnoop_test = BTSnoop('/home/omega-coder/Documents/ctfs/root-me/networking/bluetooth/ch18.bin')
    recs = BTSnoop_test.parse()
    print(list(recs)[0]) 

#!/usr/bin/env python3

# coding : utf-8


MAGIC_NUMBER__ = ['\x62', '\x74', '\x73', '\x6e', '\x6f', '\x6f', '\x70', '\x00']

class BTSnoop(object):
    def __init__(self, file_path):
        try:
            btsnoop_dump = open(file_path, 'rb')
            self.data = btsnoop_dump.read()
        except IOError, (errorno, strerror):
            print("I/O Error({}): {}".format(errorno, strerror))



if __name__ == "__main__":
    main()

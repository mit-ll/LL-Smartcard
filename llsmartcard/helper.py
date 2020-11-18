# Copyright 2015, MASSACHUSETTS INSTITUTE OF TECHNOLOGY
# Subject to FAR 52.227-11 – Patent Rights – Ownership by the Contractor (May 2014).
# SPDX-License-Identifier: BSD-3-Clause

def write_binary(data, filename):
    """
        Write binary data to a file on disk
    """

    import struct

    # Create file and write to it
    f = open(filename, "wb+")

    f.write(struct.pack("%dB" % len(data), *data))

    f.close()

def read_binary(filename):
    """
        Write binary data to a file on disk
    """
    import struct

    data = []

    # Create file and write to it
    f = open(filename, "rb")

    byte = f.read(1)
    while byte != b"":

        data.append(ord(byte))

        # Do stuff with byte.
        byte = f.read(1)


    f.close()

    return data

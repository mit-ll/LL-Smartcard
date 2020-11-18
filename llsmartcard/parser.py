# Copyright 2015, MASSACHUSETTS INSTITUTE OF TECHNOLOGY
# Subject to FAR 52.227-11 – Patent Rights – Ownership by the Contractor (May 2014).
# SPDX-License-Identifier: BSD-3-Clause

# Native
import logging
import sys
logger = logging.getLogger(__name__)

# 3rd Party
import smartcard
from smartcard.System import readers

def command_line(opts, callback, args=None):

    opts.add_option("-l", "--listreaders", action="store_true",
        dest="listreaders", default=False,
        help="List Available Readers")

    opts.add_option("-r", "--reader", action="store", type="int",
        dest="reader", default= -1,
        help="Reader number from --list or -1 for all.")

    opts.add_option("-d", "--debug", action="store_true",
        dest="debug", default=False,
        help="Enable DEBUG")
    # Get arguments
    (options, positionals) = opts.parse_args(args)
    # Enumerate Readers
    reader_list = readers()

    # Get our log level
    if options.debug:
#        log_level = logging.DEBUG
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig()
        
    if len(reader_list) == 0:
        logger.error("No readers found.")
            
    if options.listreaders:
        print "Available readers: "
        for i in range(len(reader_list)):
            print "  %d: %s" % (i, reader_list[i])
        return

    # Walk over all readers
    for i in range(len(reader_list)):
        if options.reader == i or options.reader < 0:
            try:
                # Connect to Reader
                print "Using: %s" % reader_list[i]
                connection = reader_list[i].createConnection()
                connection.connect()
                # process card in reader
                callback(connection, options)
                break

            except smartcard.Exceptions.CardConnectionException:
                print "ERROR: Couldn't connect to card in %s" % reader_list[i]
                sys.exit(0)


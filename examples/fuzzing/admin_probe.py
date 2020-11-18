"""
 Copyright 2015, MASSACHUSETTS INSTITUTE OF TECHNOLOGY
 Subject to FAR 52.227-11 – Patent Rights – Ownership by the Contractor (May 2014).
 SPDX-License-Identifier: BSD-3-Clause

    This is just a simple program to test all instructions in a given class
"""
# Navtive
import logging
import optparse

# LL Smartcard 
import llsmartcard.apdu as APDU
from llsmartcard.card import SmartCard, VisaCard, CAC

# Globals
log_level = logging.ERROR

def process_card(connection, options):
    global log_level

    # Which CLA to probe?
    PROBE_CLA = 0xFF

    # Open card
    card = CAC(connection)

    print "Trying some interesting APDUs"
    
    for i in range(0xff+1):
        for j in range(0xff+1):
            apdu_data = APDU.READ_BINARY(i, j, CLA=PROBE_CLA)
            data, sw1, sw2  = card._send_apdu(apdu_data)
            if sw1 == 0x90:
                print "Success at %x %x"%(i,j)
                print data
    
#     apdu_data = APDU.GET_DATA(0x00, 0x01, CLA=0xFF)
#     card._send_apdu(apdu_data)
if __name__ == "__main__":

    # Import our command line parser
    from llsmartcard import parser
    opts = optparse.OptionParser()

    # parse user arguments
    parser.command_line(opts, process_card)

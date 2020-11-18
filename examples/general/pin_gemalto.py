"""
 Copyright 2015, MASSACHUSETTS INSTITUTE OF TECHNOLOGY
 Subject to FAR 52.227-11 – Patent Rights – Ownership by the Contractor (May 2014).
 SPDX-License-Identifier: BSD-3-Clause

    This program will attempt PIN authentication, and the use the secure channel
    to reset the PN retry counter.
"""
# Navtive
import logging
logger = logging.getLogger(__name__)
import optparse

# LL Smartcard 
import llsmartcard.apdu as APDU
from llsmartcard.card import SmartCard


def process_card(connection, options):
    """
        Implement your function here
    """
    global log_level

    # Open card
    card = SmartCard(connection)


    # Try sending a valid PIN
    PIN = "1234"
    PIN_DATA = []
    for c in PIN:
        PIN_DATA.append(ord(c))

    PIN_DATA2 = list(PIN_DATA)
    PIN_DATA2[0] = 0x30
    
    print "Set PIN data:"
    print PIN
    print PIN_DATA


    # try global pin
    print "TRYING GLOBAL PIN"
    (data, sw1, sw2) = card.apdu_verify_pin([], 0x00, 0)
    (data, sw1, sw2) = card.apdu_verify_pin(PIN_DATA, 0x00)


    print "\n\n\n"

    
##    # Lock Card
#    for x in range(3):
#        (data, sw1, sw2) = card.apdu_verify_pin(PIN_DATA, 0x80)
#
#    for x in range(3):
#        (data, sw1, sw2) = card.apdu_reset_retry_counter(PIN_DATA, 0x80, PIN_DATA)


    print "Opening Secure Channel"
    
    # Select GP Manager
    card.apdu_select_application(APDU.APPLET.SECURITY_GEMALTO)
    # Open our secure channel
    card.open_secure_channel(APDU.APPLET.SECURITY_GEMALTO,
                             APDU.AUTH_KEYS.GEMALTO,
                             security_level=APDU.SECURE_CHANNEL.MODE.NONE)


    # Reset our retry counter
    print "Resetting retry counter..."
#    card.apdu_change_reference_data(0x00, [], PIN_DATA, first=True)
    card.apdu_change_reference_data(0x80, PIN_DATA, PIN_DATA)
    card.apdu_reset_retry_counter(PIN_DATA, 0x80, PIN_DATA)

    # Print applications on the card
    print "Printing card applications..."
    card.print_applications()


if __name__ == "__main__":

    # Import our command line parser
    from llsmartcard import parser
    opts = optparse.OptionParser()

    # parse user arguments
    parser.command_line(opts, process_card)

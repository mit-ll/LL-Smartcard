"""
 Copyright 2015, MASSACHUSETTS INSTITUTE OF TECHNOLOGY
 Subject to FAR 52.227-11 – Patent Rights – Ownership by the Contractor (May 2014).
 SPDX-License-Identifier: BSD-3-Clause

    This program is meant to handle secure channel communications using default
    keys.
"""
# Navtive
import logging
import optparse

# LL Smartcard 
import llsmartcard.apdu as APDU
from llsmartcard.card import CAC

# Globals
log_level = logging.ERROR

def process_card(connection, options):
    """
        Implement your function here
    """
    global log_level

    # Open card
    card = CAC(connection, log_level=log_level)

    # Select GP Manager
    card.apdu_select_application(APDU.APPLET.SECURITY_GEMALTO)
    # Open our secure channel
    card.open_secure_channel(APDU.APPLET.SECURITY_GEMALTO, APDU.AUTH_KEYS.GEMALTO)

    # Try locking the card
#    card.apdu_set_status(APDU.SET_STATUS_PARAM.TYPE.SECURITY_DOMAIN,
#                         APDU.SET_STATUS_PARAM.STATE_CARD.LOCKED)


    # List all applications
    card.print_applications()


if __name__ == "__main__":

    # Import our command line parser
    from llsmartcard import parser
    opts = optparse.OptionParser()

    # Add any options we want here
    opts.add_option("-s", "--sample", action="store_true",
        dest="sample", default=False,
        help="Sample")

    # parse user arguments
    parser.command_line(opts, process_card)

# Copyright 2015, MASSACHUSETTS INSTITUTE OF TECHNOLOGY
# Subject to FAR 52.227-11 – Patent Rights – Ownership by the Contractor (May 2014).
# SPDX-License-Identifier: BSD-3-Clause

"""
    This a nice simple reference implementation when creating new smartcard
    programs using the LL-Smartcard API
"""
# Navtive
import logging
logger = logging.getLogger(__name__)
import sys
import optparse

# LL Smartcard 
from llsmartcard.card import CreditCard


# Service code decoder
service_first = {
    '1': 'International interchange OK',
    '2': 'International interchange, use IC (chip) where feasible',
    '5': 'National interchange only except under bilateral agreement',
    '6': 'National interchange only except under bilateral agreement, use IC (chip) where feasible',
    '7': 'No interchange except under bilateral agreement (closed loop)',
    '9': 'Test'
}
service_second = {
    '0': 'Normal',
    '2': 'Contact issuer via online means',
    '4': 'Contact issuer via online means except under bilateral agreement'
}
service_third = {
    '0': 'No restrictions, PIN required',
    '1': 'No restrictions',
    '2': 'Goods and services only (no cash)',
    '3': 'ATM only, PIN required',
    '4': 'Cash only',
    '5': 'Goods and services only (no cash), PIN required',
    '6': 'No restrictions, use PIN where feasible',
    '7': 'Goods and services only (no cash), use PIN where feasible'
}


def process_card(connection, options):
    """
        Implement your function here
    """

    # Open card
    card = CreditCard(connection)
    
    # Select
    if options.card_type == "V": 
        print "* Reading VISA card..."
        card.select_visa_applet()
    elif options.card_type == "M":
        print "* Reading MasterCard..."
        card.select_mastercard_applet()
    else:
        logger.error("Unrecognized card type.")
        return
#     card.dump_records()
    
    cc_info = card.read_card_info()
    
    if cc_info is not None:
            print "Bank card info: "
            print " * Name: %s %s"%(cc_info['first_name'],cc_info['last_name'])
            print " * Account #: %s"%(cc_info['account_number'])
            print " * Expiration: %s/%s"%(cc_info['exp_month'], cc_info['exp_year'])
            print " * Service: %s"%(service_first[cc_info['service_first']])
            print "            %s"%(service_second[cc_info['service_second']])
            print "            %s"%(service_third[cc_info['service_third']])
    

if __name__ == "__main__":

    # Import our command line parser
    from llsmartcard import parser
    opts = optparse.OptionParser()

    # Add any options we want here
    opts.add_option("-t", "--card_type", action="store",
        dest="card_type", default="V",
        help="Type of card (V - VISA, M - MasterCard")

    # parse user arguments
    parser.command_line(opts, process_card)
    
    

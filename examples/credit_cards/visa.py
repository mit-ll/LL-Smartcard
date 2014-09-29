"""
    This a nice simple reference implementation when creating new smartcard
    programs using the LL-Smartcard API
"""
# Navtive
import logging
import optparse

# LL Smartcard 
from llsmartcard.card import VisaCard

def process_card(connection, options):
    """
        Implement your function here
    """

    # Open card
    card = VisaCard(connection)
    
    # Select 
    card.select_visa_applet()
    card.read_visa()
    

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
    
    
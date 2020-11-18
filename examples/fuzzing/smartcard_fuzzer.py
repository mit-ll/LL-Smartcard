"""
 Copyright 2015, MASSACHUSETTS INSTITUTE OF TECHNOLOGY
 Subject to FAR 52.227-11 – Patent Rights – Ownership by the Contractor (May 2014).
 SPDX-License-Identifier: BSD-3-Clause

    This application was made to enumerate all of the APDUs on a card
    
    This specific example first selects the CAC's PIV applet before fuzzing.
"""

# Native
import sys
import logging
#logging.basicConfig(level=logging.DEBUG)

# 3rd party (PyScard)
from smartcard.System import readers
from smartcard.sw.ISO7816_4ErrorChecker import ISO7816_4ErrorChecker
from smartcard.sw.ISO7816_8ErrorChecker import ISO7816_8ErrorChecker
from smartcard.sw.ISO7816_9ErrorChecker import ISO7816_9ErrorChecker
from smartcard.sw.ErrorCheckingChain import ErrorCheckingChain
from smartcard.sw.SWExceptions import SWException

# LL Smartcard
import llsmartcard.apdu as APDU
from llsmartcard.apdu import APDU_STATUS, APPLET
from llsmartcard.card import SmartCard, CAC

# Setup our error chain
errorchain = []
errorchain = [ ErrorCheckingChain(errorchain, ISO7816_9ErrorChecker()),
            ErrorCheckingChain(errorchain, ISO7816_8ErrorChecker()),
            ErrorCheckingChain(errorchain, ISO7816_4ErrorChecker()) ]

# List of valid classes and insructions
valid_cla = []
valid_ins = []

# Hash tables to help aggregate findings
cla_sw_ins = {}
sw_ins_cla = {}

"""
    Functions to support hash table insertion
"""
def insert_success(cla, ins, p1, p2, sw1, sw2):
    """
        Insert a succesful response into our valid list
    """
    global valid_ins
    valid_ins.append((cla, ins, (p1, p2), (sw1, sw2)))
    successful_apdu = "%04s %04s %04s %04s %04s %04s" % (hex(cla),
                                                             hex(ins),
                                                             hex(p1),
                                                             hex(p2),
                                                             hex(sw1),
                                                             hex(sw2)
                                                             )
    print "Got Success: %s" % successful_apdu
    

def insert_trial(cla, ins, sw1, sw2):
    """
        Insert a trial with status word response into our structures
    """
    global cla_sw_ins, sw_ins_cla

    sw = sw1 << 8 | sw2

    # Depth = 1
    if cla not in cla_sw_ins:
        cla_sw_ins[cla] = {}
    if sw not in sw_ins_cla:
        sw_ins_cla[sw] = {}

    # Depth = 2
    if ins not in sw_ins_cla[sw]:
        sw_ins_cla[sw][ins] = []
    if ins not in cla_sw_ins[cla]:
        cla_sw_ins[cla][sw] = []

    # Add the nugget
    sw_ins_cla[sw][ins].append(cla)
    cla_sw_ins[cla][sw].append(ins)


"""
    Functions to handle output
"""
def open_file(filename):
    """
        Open the given filename for writing or default to standard out
    """
    if filename is None:
        output = sys.stdout
    else:
        try:
            output = open(filename, "w+")
        except:
            logging.error("Couldn't open %s." % filename)
            output = sys.stdout

    return output

def print_cla_sw_ins(filename=None):
    """
        Print CLAss, Status Word, INStruction into a tab-delimited file
    """
    output = open_file(filename)

    output.write("%04s\t%06s\t%s\n" % ("CLA", "SW", "INS(s)"))
    for cla in cla_sw_ins:
        for sw in cla_sw_ins[cla]:
            output.write("%04s\t%06s\t" % (hex(cla), hex(sw)))
            for ins in cla_sw_ins[cla][sw]:
                output.write("%s " % hex(ins))
            output.write("\n")

    if output != sys.stdout:
        output.close()



def print_sw_ins_cla(filename=None):
    """
        Print Status Word, INStruction, CLAss into a tab-delimited file
    """
    output = open_file(filename)

    output.write("%06s\t%04s\t%s\n" % ("SW", "INS", "CLA(s)"))
    for sw in sw_ins_cla:
        for ins in sw_ins_cla[sw]:
            output.write("%06s\t%04s\t" % (hex(sw), hex(ins)))
            for cla in sw_ins_cla[sw][ins]:
                output.write("%s " % hex(cla))
            output.write("\n")

    if output != sys.stdout:
        output.close()

def print_success(filename=None):
    """
        Print all successful responses to filename
    """
    
    output = open_file(filename)

    output.write("%04s %04s %04s %04s %04s %04s\n" % ("CLA", "INS", "P1", "P2", "SW1", "SW2"))

    for valid in valid_ins:
        (cla, ins, (p1, p2), (sw1, sw2)) = valid
        successful_apdu = "%04s %04s %04s %04s %04s %04s" % (hex(cla),
                                                             hex(ins),
                                                             hex(p1),
                                                             hex(p2),
                                                             hex(sw1),
                                                             hex(sw2)
                                                             )
        output.write(successful_apdu + "\n")

    if output != sys.stdout:
        output.close()

"""
    Functions for interacting with the card
"""
def send_apdu(card, apdu_to_send):
    """
        Send an APDU to the card, and hadle errors appropriately
    """
    str = "Trying : ", [hex(i) for i in apdu_to_send]
    logging.debug(str)
    try:
        (data, sw1, sw2) = card._send_apdu(apdu_to_send)
        errorchain[0]([], sw1, sw2)

    except SWException, e:
        # Did we get an unsuccessful attempt?
        logging.info(e)
    except:
        logging.warn("Oh No! Pyscard crashed...")
        (data, sw1, sw2) = ([], 0xFF, 0xFF)

    str = "Got : ", data, hex(sw1), hex(sw2)
    logging.debug(str)

    return (data, sw1, sw2)

def fuzzer(card, args=None):
    """
        Enumerate all valid classes, and brute force all instructions on those
        classes, recording the results
    """
    # First, determine all possible valid command classes
    print "Enumerating valid classes..."
    for cla in range(0xFF + 1):
        # CLS INS P1 P2
        apdu_to_send = [cla, 0x00, 0x00, 0x00]

        (data, sw1, sw2) = send_apdu(card, apdu_to_send)

        # unsupported class is 0x6E00
        if (sw1 == 0x6E) and (sw2 == 0x00):
            continue
        else:
            valid_cla.append(cla)

    # Print our valid classes
    print "Found %d valid command classes: " % len(valid_cla),
    for cla in valid_cla:
        print "%s" % hex(cla),
    print ""

    # Try our best not to lock up the card
    BAD_INSTRUCTIONS = [APDU.APDU_CMD.VERIFY, APDU.APDU_CMD.CHANGE_REF_DATA]

    # Next, try all possible instruction values for each valid command class
    print "Brute forcing every command for each class..."
    for cla in range(0xFF + 1):
        for ins in range(0xFF + 1):
            if ins in BAD_INSTRUCTIONS:
                continue

            # Start our parameters at 0x00
            p1 = 0x00
            p2 = 0x00

            # CLS INS P1 P2
            apdu_to_send = [cla, ins, p1, p2]

            # Send APDU
            (data, sw1, sw2) = send_apdu(card, apdu_to_send)

            # What values do we consider a success? 
            SUCCESS_LIST = [0x90, # Success
                            0x61, # More Data
                            0x67, # Wrong Length
                            0x6c, # Wrong Length
                            0x6a, # Referenced Data not found
#                            0x69 # Access Violation (Not sure about this)
                            ]

            SUCCESS_BAD_PARAM = [(0x6a, 0x86) #Incorrect Paramters
                                 ]
            SUCCESS_FAIL = [(0x6a, 0x81) # Funciton not supported
                            ]

            # Success?
            if sw1 in SUCCESS_LIST:
                if (sw1, sw2) not in SUCCESS_FAIL:
                    insert_success(cla, ins, p1, p2, sw1, sw2)

            # Check to see if the command was "successful" and tweak permissions
            # until we get a 0x9000
            if (sw1, sw2) in SUCCESS_BAD_PARAM:
                logging.info("Got partial success, trying to find proper parameters..")

#                # Brute force Parameters
#                for p1 in range(0xff + 1):
#                    for p2 in range(0xff + 1):
#
#                        # CLS INS P1 P2
#                        apdu_to_send = [cla, ins, p1, p2]
#
#                        # Send APDU
#                        (data, sw1, sw2) = send_apdu(apdu_to_send)
#
#                        # Check status
#                        if sw1 in SUCCESS_LIST:
#                            valid_ins.append((cla, ins, (p1, p2), (sw1, sw2)))



            # unsupported command is 0x6d00
    #        if (sw1 == 0x6d) and (sw2 == 0x00):
    #            continue
#            if (sw1, sw2) not in [(0x6d, 0x00), (0x68, 0x84)]:
#                valid_ins.append((cla, ins))

            # Add response to hash tables
            insert_trial(cla, ins, sw1, sw2)

    print "Found %d valid instructions." % len(valid_ins)

    print "Saving results..."

    print_cla_sw_ins("cla_sw_ins.tsv")
    print_sw_ins_cla("sw_ins_cla.tsv")
    print_success("successes.txt")

    print "Done."



if __name__ == "__main__":
    # get readers
    reader_list = readers()
    
    # Let the user the select a reader
    if len(reader_list) > 1:
        print "Please select a reader"
        idx = 0
        for r in reader_list:
            print "  %d - %s"%(idx,r)
            idx += 1
            
        reader_idx = -1
        while reader_idx < 0 or reader_idx > len(reader_list)-1:
            reader_idx = int(raw_input("Reader[%d-%d]: "%(0,len(reader_list)-1)))
        
        reader = reader_list[reader_idx]
    else:
        reader = reader_list[0]
    
    print "Using: %s" % reader
    
    # create connection
    connection = reader.createConnection()
    connection.connect()
    
    # do stuff with CAC
    card = CAC(connection)
    card.select_nist_piv()

    # Call our fuzzer
    fuzzer(card)


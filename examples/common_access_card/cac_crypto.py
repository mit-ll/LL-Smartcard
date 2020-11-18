"""
Copyright 2015, MASSACHUSETTS INSTITUTE OF TECHNOLOGY
Subject to FAR 52.227-11 – Patent Rights – Ownership by the Contractor (May 2014).
SPDX-License-Identifier: BSD-3-Clause

 	This application was made to interact with the cryptographic functions
	on the CAC cards.  While it does not folow our template format, the 
	features of llsmartcard utilized are still relevant.
"""
import sys
import logging
logger = logging.getLogger(__name__)
import optparse
import subprocess
import os
import struct
from subprocess import call

# 3rd Party
import smartcard
from smartcard.System import readers
import llsmartcard.apdu as APDU
import llsmartcard.helper as HELPER
from llsmartcard.apdu import APPLET

# LL Smartcard
from llsmartcard.card import CAC

CAC_KEYS = []
CAC_APPLET_OBJECTS = APDU.OBJ_DOD_CAC
for var in CAC_APPLET_OBJECTS.__dict__:
    if var.startswith("KEY"):
        CAC_KEYS.append(var)

def extract_certs(card, path):
    """
        This function will extract all of the certificates froma  CAC to a given directory

	    @param card - SmartCard object
        @param path - Path to dump raw certs to
    """
    
    logger.info("Dumping Certificates from CAC...")

    try:
        os.makedirs(path)
    except:
        pass

    # Dump CHUID Cert
    cert_filename = os.path.join(path,
                                "chuid.crt")
    card.extract_cert(APPLET.NIST_PIV,
                      APDU.OBJ_NIST_PIV.CHUID,
                      cert_filename)

    # Create our output directories
    nist_dir = os.path.join(path, "piv")
    cac_dir = os.path.join(path, "cac")
    try:
        os.makedirs(nist_dir)
        os.makedirs(cac_dir)
    except:
        pass

    """
         NIST PIV CERTS
         These are all gzipped and DER format
    """
    # Dig Sig
    nist_dig_sig = os.path.join(nist_dir, "nist_dig_sig.crt")
    card.save_nist_cert(APDU.OBJ_NIST_PIV.KEY_DIG_SIG, nist_dig_sig)

    # PIV Auth
    nist_auth = os.path.join(nist_dir, "nist_piv_auth.crt")
    card.save_nist_cert(APDU.OBJ_NIST_PIV.KEY_PIV_ATH, nist_auth)

    # Key Management
    nist_mng = os.path.join(nist_dir, "nist_mng.crt")
    card.save_nist_cert(APDU.OBJ_NIST_PIV.KEY_MNG, nist_mng)

    """
        DoD CAC Certs
        Unsure of the format of these...
    """
    # PKI Encryption Key (Same as NIST Key Mng Key)
    cac_enc = os.path.join(cac_dir, "cac_pki_enc.crt")
    card.extract_cert(APPLET.DOD_CAC,
                      APDU.OBJ_DOD_CAC.KEY_PKI_ENC,
                      cac_enc)
    # PKI ID key
    cac_id = os.path.join(cac_dir, "cac_pki_id.crt")
    card.extract_cert(APPLET.DOD_CAC,
                      APDU.OBJ_DOD_CAC.KEY_PKI_ID,
                      cac_id)
    # PKI Dig Sig
    cac_pki_sig = os.path.join(cac_dir, "cac_pki_sig.crt")
    card.extract_cert(APPLET.DOD_CAC,
                      APDU.OBJ_DOD_CAC.KEY_PKI_SIG,
                      cac_pki_sig)

    # Symbolically link the identical keys (CAC End-Piont Implementation Guide v1.22)
    subprocess.Popen(["ln", "-s", "-f", "../../" + nist_dig_sig + ".pub", cac_pki_sig + ".pub"])
    subprocess.Popen(["ln", "-s", "-f", "../../" + nist_mng + ".pub", cac_enc + ".pub"])


def main(args=None):

    opts = optparse.OptionParser()

    opts.add_option("-r", "--reader", action="store", type="int",
        dest="reader", default= -1,
        help="Reader number from --list or -1 for all.")

    opts.add_option("-R", "--listreaders", action="store_true",
        dest="listreaders", default=False,
        help="List Available Readers")

    opts.add_option("-E", "--encrypt", action="store_true",
        dest="encrypt", default=False,
        help="Do a public key encryption.")

    opts.add_option("-D", "--decrypt", action="store_true",
        dest="decrypt", default=False,
        help="SIGN/DECRYPT using the smartcard.")

    opts.add_option("-S", "--signd", action="store_true",
        dest="sign", default=False,
        help="SIGN/DECRYPT using the smartcard.")


    opts.add_option("-d", "--debug", action="store_true",
        dest="debug", default=False,
        help="Enable DEBUG")

    opts.add_option("-x", "--certs", action="store", type="string",
        dest="savecerts", default=None,
        help="Extract all of the certificates to specified directory.")

    opts.add_option("-i", "--input", action="store", type="string",
        dest="input", default=None,
        help="Input file.")

    opts.add_option("-o", "--output", action="store", type="string",
        dest="output", default=None,
        help="Output file.")

    opts.add_option("-k", "--pubkey", action="store", type="string",
        dest="pubkey", default=None,
        help="Public key to use for crytographic operations.")

    opts.add_option("-c", "--cert", action="store", type="string",
        dest="cert", default=None,
        help="Certificate to use for SIGN/DECRYPT command. %s" % CAC_KEYS)

    opts.add_option("-p", "--pin", action="store", type="string",
        dest="pin", default=None,
        help="PIN for the CAC card.  (WARNING: 3 failed attempts will lock the card.)")

    (options, positionals) = opts.parse_args(args)

    # List our readers
    reader_list = readers()
    if options.listreaders:
        print "Available readers: "
        for i in range(len(reader_list)):
            print "  %d: %s" % (i, reader_list[i])
        return

    # Set our logging level
    log_level = logging.ERROR
    if options.debug:
        log_level = logging.DEBUG

    for i in range(len(reader_list)):
        if options.reader == i or options.reader < 0:
            try:
                print "Using: %s" % reader_list[i]

                connection = reader_list[i].createConnection()
                connection.connect()
                card = CAC(connection, log_level=log_level)

                # Enter the PIN to use for authorized APDUs
                PIN = [0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37]
                if options.pin is not None:
                    PIN = []
                    for a in range(len(options.pin)):
                        PIN.append(ord(options.pin[a]))

                # What function are we performing?
                if options.savecerts is not None:
                    extract_certs(card, options.savecerts)

                # Encrypt a file using a public key?
                if options.encrypt:
                    # Check params
                    if options.input is None:
                        print "ERROR: No input file given."
                        opts.print_usage()
                        sys.exit()
                    if options.pubkey is None:
                        print "ERROR: No public key file given."
                        opts.print_usage()
                        sys.exit()
                    if options.output is None:
                        print "ERROR: No output file given."
                        opts.print_usage()
                        sys.exit()

                    # Use openssl
                    call(["openssl", "pkeyutl", "-encrypt",
                          "-in", options.input,
                          "-pubin",
                          "-inkey", options.pubkey,
                          "-out", options.output])

                    print "Encrypted %s using %s -> %s." % (options.input,
                                                         options.pubkey,
                                                         options.output)

                if options.decrypt or options.sign:
                    # Check params
                    if options.input is None:
                        print "ERROR: No input file given."
                        opts.print_usage()
                        sys.exit()
                    if options.cert is None:
                        print "ERROR: No CAC certificate selected."
                        opts.print_usage()
                        sys.exit()
                    if options.output is None:
                        print "ERROR: No output file given."
                        opts.print_usage()
                        sys.exit()
                    if options.cert not in CAC_KEYS:
                        print "ERROR: not valid key selected."
                        opts.print_usage()
                        sys.exit()
                    if options.pin is None or len(PIN) < 4:
                        print "ERROR: No PIN given to authenticate to card."
                        opts.print_usage()
                        sys.exit()

                    # VERIFY PIN
                    logger.info("Verfying PIN...")
                    data, sw1, sw2 = card.apdu_verify_pin(PIN, 0x00)

                    # Select CAC Applet
                    logger.info("Selecting CAC Applet...")
                    card.apdu_select_application(APDU.APPLET.DOD_CAC)

                    # Select appropriate key
                    logger.info("Selecting appropriate key...")
                    cur_key = CAC_APPLET_OBJECTS.__dict__[options.cert]
                    card.apdu_select_object(cur_key)

                    # Read input
                    sign_data = HELPER.read_binary(options.input)

                    data, sw1, sw2 = card.apdu_sign_decrypt(sign_data)

                    HELPER.write_binary(data, options.output)

                    print "Decrypted %s -> %s." % (options.input, options.output)

                    for i in range(len(data)):
                        if data[i] == 0x00 and i != 0:
                            print "ASCII: %s" % APDU.get_str(data[i:-1])


            except smartcard.Exceptions.CardConnectionException as ex:
                print "ERROR: Couldn't connect to card in %s" % reader_list[i]


if __name__ == "__main__":
    main()

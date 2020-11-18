# Copyright 2015, MASSACHUSETTS INSTITUTE OF TECHNOLOGY
# Subject to FAR 52.227-11 – Patent Rights – Ownership by the Contractor (May 2014).
# SPDX-License-Identifier: BSD-3-Clause

# Navtive
import sys
import logging
import optparse
import subprocess
from subprocess import call

# 3rd Party
import smartcard
from smartcard.System import readers
import llsmartcard.apdu as APDU
from llsmartcard.apdu import APDU_STATUS, APPLET
# LL Smartcard
from llsmartcard.card import SmartCard, VisaCard, CAC


class CARD_TYPE:
    VISA = 0
    CAC = 1
    HELLO_WORLD = 2
    EXPERIMENT = 3
    SECURE = 4

CARD_TYPES = {  "V":CARD_TYPE.VISA,
                "C":CARD_TYPE.CAC,
                "H":CARD_TYPE.HELLO_WORLD,
                "E":CARD_TYPE.EXPERIMENT,
                "S":CARD_TYPE.SECURE}

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

def main(args=None):

    opts = optparse.OptionParser()

    opts.add_option("-t", "--cardtype", action="store", type="string",
        dest="cardtype", default=CARD_TYPE.CAC,
        help="Card Type (V - Visa, C - CAC, H - Hello World)")

    opts.add_option("-l", "--listreaders", action="store_true",
        dest="listreaders", default=False,
        help="List Available Readers")

    opts.add_option("-s", "--savecerts", action="store", type="string",
        dest="savecerts", default=None,
        help="Save certificates to disk.")

    opts.add_option("-r", "--reader", action="store", type="int",
        dest="reader", default= -1,
        help="Reader number from --list or -1 for all.")

    opts.add_option("-d", "--debug", action="store_true",
        dest="debug", default=False,
        help="Enable DEBUG")



    (options, positionals) = opts.parse_args(args)

    if options.cardtype in CARD_TYPES:
        card_type = CARD_TYPES[options.cardtype]
    else:
        print "Card type not recognized."
        card_type = CARD_TYPE.CAC

    reader_list = readers()
    if options.listreaders:
        print "Available readers: "
        for i in range(len(reader_list)):
            print "  %d: %s" % (i, reader_list[i])
        return

    log_level = logging.ERROR
    if options.debug:
        log_level = logging.DEBUG

    # by default we use the first reader
    for i in range(len(reader_list)):
        if options.reader == i or options.reader < 0:
            try:
                print "Using: %s" % reader_list[i]

                connection = reader_list[i].createConnection()
                connection.connect()


                if card_type == CARD_TYPE.SECURE:

                    card = SmartCard(connection, log_level=log_level)
                    card.apdu_select_application(APDU.APPLET.SECURITY_GEMALTO)
                    card.open_secure_channel(APDU.APPLET.SECURITY_GEMALTO, APDU.AUTH_KEYS.GEMALTO)
                    card.print_applications()
                    for p1 in range(0xff):
                        for p2 in range(0xff):

                            data, sw1, sw2 = card.apdu_get_data([p1, p2])

                            if (sw1, sw2) != APDU.STATUS_WORDS.NOT_FOUND and (sw1, sw2) != APDU.STATUS_WORDS.COND_NOT_SATISFIED:
                                print "(%s,%s) %s %s: %s" % (hex(sw1), hex(sw2),
                                                             hex(p1), hex(p2),
                                                   APDU.get_hex(data))

                if card_type == CARD_TYPE.VISA:
                    card = VisaCard(connection, log_level=log_level)
                    card.select_visa_applet()
                    card.read_visa()

                if card_type == CARD_TYPE.HELLO_WORLD:
                    card = SmartCard(connection, log_level=log_level)
                    card.apdu_select_application(APDU.APPLET.HELLO)
                    data, sw1, sw2 = card.apdu_read_record(0x00, 0x00)
                    print "Data: %s" % APDU.get_str(data)

                if card_type == CARD_TYPE.CAC:
                    card = CAC(connection, log_level=log_level)

                    card.print_object(APPLET.NIST_PIV,
                                          APDU.OBJ_NIST_PIV.CHUID)
                    card.print_object(APPLET.NIST_PIV,
                                          APDU.OBJ_NIST_PIV.CCC)

                    if options.savecerts is not None:
                        print "Dumping Certs"

                        import os
                        import struct

                        try:
                            os.makedirs(options.savecerts)
                        except:
                            pass

                        # Dump CHUID Cert
                        cert_filename = os.path.join(options.savecerts,
                                                    "chuid.crt")
                        card.extract_cert(APPLET.NIST_PIV,
                                          APDU.OBJ_NIST_PIV.CHUID,
                                          cert_filename)


                        # NIST PIV CERTS
                        # These are all gzipped
                        def extract_nist(oid, cert_filename):

                            card.extract_cert(APPLET.NIST_PIV,
                                              oid,
                                              cert_filename)
                            # ungzip it
                            call(["gunzip", "-f", cert_filename])
                            cert_filename = cert_filename[0:-3]
                            # extract public cert

                            p = subprocess.Popen(["openssl", "x509",
                                                  "-inform", "DER",
                                                  "-pubkey",
                                                   "-in", cert_filename,
                                                   "-out", cert_filename + ".pem"],
                                                  stdout=subprocess.PIPE)
                            out, err = p.communicate()
                            f = open(cert_filename + ".pub", "w+")
                            f.write(out)
                            f.close()

                        nist_dir = os.path.join(options.savecerts, "piv")
                        try:
                            os.makedirs(nist_dir)
                        except:
                            pass


                        # Dig Sig
                        cert_filename = os.path.join(nist_dir,
                                                    "nist_dig_sig.crt.gz")
                        extract_nist(APDU.OBJ_NIST_PIV.KEY_DIG_SIG, cert_filename)


#                        call(, "> %s.pub" % cert_filename])

                        # PIV Auth
                        cert_filename = os.path.join(nist_dir,
                                                    "nist_piv_auth.crt.gz")
                        extract_nist(APDU.OBJ_NIST_PIV.KEY_PIV_ATH, cert_filename)

                        # Doesn't seem to exist...
#                        # Cred Auth
#                        cert_filename = os.path.join(nist_dir,
#                                                    "nist_crd_auth.crt.gz")
#                        extract_nist(APDU.OBJ_NIST_PIV.KEY_CRD_ATH, cert_filename)


                        # Key Management
                        cert_filename = os.path.join(nist_dir,
                                                    "nist_mng.crt.gz")
                        extract_nist(APDU.OBJ_NIST_PIV.KEY_MNG, cert_filename)

                        #
                        # DoD CAC Certs
                        #
                        cac_dir = os.path.join(options.savecerts, "cac")
                        try:
                            os.makedirs(cac_dir)
                        except:
                            pass


                        cert_filename = os.path.join(cac_dir,
                                                    "cac_pki_enc.pub")
                        card.extract_cert(APPLET.DOD_CAC,
                                          APDU.OBJ_DOD_CAC.KEY_PKI_ENC,
                                          cert_filename)

                        cert_filename = os.path.join(cac_dir,
                                                    "cac_pki_id.pub")
                        card.extract_cert(APPLET.DOD_CAC,
                                          APDU.OBJ_DOD_CAC.KEY_PKI_ID,
                                          cert_filename)

                        cert_filename = os.path.join(cac_dir,
                                                    "cac_pki_sig.pub")
                        card.extract_cert(APPLET.DOD_CAC,
                                          APDU.OBJ_DOD_CAC.KEY_PKI_SIG,
                                          cert_filename)

#                        nist_dig_sig_f = open(nist_dig_sig, "wb")
#
#                        # NIST PIV
#                        data = card.read_object(APPLET.NIST_PIV,
#                                          APDU.OBJ_NIST_PIV.KEY_DIG_SIG)
#                        print APDU.get_hex(data[0][1])
#                        for i in data[0][1]:
#                            nist_dig_sig_f.write(struct.pack("B", i))
#
#                        nist_dig_sig_f.close()

#                        card.print_object(APPLET.NIST_PIV,
#                                          APDU.OBJ_NIST_PIV.KEY_MNG)
                        card.print_object(APPLET.NIST_PIV,
                                          APDU.OBJ_NIST_PIV.KEY_PIV_ATH)
#                        card.print_object(APPLET.NIST_PIV,
#                                          APDU.OBJ_NIST_PIV.SEC_OBJ)
#
#                        # DoD CAC
                        card.print_object(APDU.APPLET.DOD_CAC,
                                          APDU.OBJ_DOD_CAC.KEY_PKI_ENC)
                        card.print_object(APDU.APPLET.DOD_CAC,
                                          APDU.OBJ_DOD_CAC.KEY_PKI_ID)
                        card.print_object(APDU.APPLET.DOD_CAC,
                                          APDU.OBJ_DOD_CAC.KEY_PKI_SIG)




                if card_type == CARD_TYPE.EXPERIMENT:

                    card = CAC(connection, log_level=log_level)

                    PIN = [0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37]


                    data, sw1, sw2 = card.apdu_verify_pin(PIN, p2=0x00)


                    card.apdu_select_application(APDU.APPLET.DOD_CAC)
                    card.apdu_select_object(APDU.OBJ_DOD_CAC.KEY_PKI_ID)

#                    data, sw1, sw2 = card.apdu_verify_pin(PIN, p2=0x80)

                    sign_data = []
                    for i in range(100):
                        sign_data.append(0x41)

                    sign_data = read_binary("input.ssl")

                    print sign_data

                    print "Signing: %s" % APDU.get_hex(sign_data)
                    data, sw1, sw2 = card.apdu_sign_decrypt(sign_data)

                    write_binary(data, "data.enc")




                    print "Signed: %s" % APDU.get_hex(data)

#                    card.apdu_select_object(APDU.OBJ_DOD_CAC.KEY_PKI_SIG)
#
#                    data, sw1, sw2 = card.apdu_sign_decrypt(data)
#
#                    print "Decrypted: %s" % APDU.get_hex(data)


#                    card.read_x509_piv(card.X509.PIV_ATH)
#
#                    card.read_x509_piv(card.X509.DIG_SIG)
#                    card.read_x509_piv(card.X509.KEY_MNG)

#                    card.read_chuid(APDU.APPLET.NIST_PIV)
#                    card.read_chuid(APDU.APPLET.DOD_PIV)
#
#                    card.read_card_capability_container(APDU.APPLET.NIST_PIV)
#                    card.read_card_capability_container(APDU.APPLET.DOD_PIV)

#                    card.apdu_select_application(APDU.APPLET.DOD_PIV, pix=APDU.OBJ_DOD_PIV.CHUID)
#                    card.apdu_select_object(APDU.OBJ_DOD_PIV.KEY_PIV_ATH)
#                    card.read_tl_v_buffer(0x0000)
#                    card.apdu_select_object(APDU.OBJ_DOD_PIV.SEC_OBJ)
#
                    if False:
                        print "Printing NIST PIV Objects..."

                        # Print NIST PIV Objects
                        card.print_object(APPLET.NIST_PIV,
                                          APDU.OBJ_NIST_PIV.CHUID)
                        card.print_object(APPLET.NIST_PIV,
                                          APDU.OBJ_NIST_PIV.CCC)
                        card.print_object(APPLET.NIST_PIV,
                                          APDU.OBJ_NIST_PIV.KEY_DIG_SIG)
                        card.print_object(APPLET.NIST_PIV,
                                          APDU.OBJ_NIST_PIV.KEY_MNG)
                        card.print_object(APPLET.NIST_PIV,
                                          APDU.OBJ_NIST_PIV.KEY_PIV_ATH)
                        card.print_object(APPLET.NIST_PIV,
                                          APDU.OBJ_NIST_PIV.SEC_OBJ)

                        # Objects that require PIN
                        card.print_object(APPLET.NIST_PIV,
                                          APDU.OBJ_NIST_PIV.KEY_CRD_ATH)
                        card.print_object(APPLET.NIST_PIV,
                                          APDU.OBJ_NIST_PIV.FACE)
                        card.print_object(APPLET.NIST_PIV,
                                          APDU.OBJ_NIST_PIV.FNGR_P1)
                        card.print_object(APPLET.NIST_PIV,
                                          APDU.OBJ_NIST_PIV.FNGR_P2)

                        print "Printing DoD PIV Objects..."

                        # Print DOD PIV Object
                        card.print_object(APPLET.DOD_PIV,
                                          APDU.OBJ_DOD_PIV.CCC)
                        card.print_object(APPLET.DOD_PIV,
                                          APDU.OBJ_DOD_PIV.SEC_OBJ,
                                          pix=APDU.PIX_CAC.PIV_TRNS_APLT)
                        card.print_object(APPLET.DOD_PIV,
                                          APDU.OBJ_DOD_PIV.FACE,
                                          pix=APDU.PIX_CAC.PIV_TRNS_APLT)
                        card.print_object(APPLET.DOD_PIV,
                                          APDU.OBJ_DOD_PIV.FNGR_PRNT,
                                          pix=APDU.PIX_CAC.PIV_TRNS_APLT)

                        # We need a PIN for the CHUID?
                        card.print_object(APPLET.DOD_PIV,
                                          APDU.OBJ_DOD_PIV.CHUID)

                        print "Printing DoD CAC Objects..."

                        # Print DOD CAC Objects
                        card.print_object(APDU.APPLET.DOD_CAC,
                                          APDU.OBJ_DOD_CAC.KEY_PKI_ENC)
                        card.print_object(APDU.APPLET.DOD_CAC,
                                          APDU.OBJ_DOD_CAC.KEY_PKI_ID)
                        card.print_object(APDU.APPLET.DOD_CAC,
                                          APDU.OBJ_DOD_CAC.KEY_PKI_SIG)

                        # Not yet sure what information is here.
                        card.print_object(APDU.APPLET.DOD_CAC,
                                          APDU.OBJ_DOD_CAC.CAC_PERSON)
                        card.print_object(APDU.APPLET.DOD_CAC,
                                          APDU.OBJ_DOD_CAC.CAC_PERSONEL)

                    sys.exit(0)

                    # PIN REQUIRED FOR THESE



                    # VERIFY PIN
                    card.apdu_select_application(APDU.APPLET.DOD_PIV, APDU.OBJ_DOD_PIV.CHUID)
                    tv_list = card.read_tl_v_buffer(0x0000)
                    for tv in tv_list:
                        print hex(tv[0])
                        print APDU.get_hex(tv[1])
#                    data, sw1, sw2 = card.apdu_read_buffer(0x00, 0x00, 01, read_length=20)
#                    data, sw1, sw2 = card.apdu_verify_pin([0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37], p2=0x01)
#                    card.select_object([0xa0, 01])

                    sys.exit(0)

                    PIN = [0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37]
                    card.apdu_select_application(APDU.APPLET.NIST_PIV)
                    card.read_chuid()

#                    card.read_fingerprint(PIN)
#                    card.read_facial_info(PIN)

                    # Try to sign/decrypt
#                    card.apdu_select_application(APDU.APPLET.NIST_PIV)
#                    card.apdu_verify_pin(PIN, p2=0x00)
#                    card.apdu_sign_decrypt([0x41, 0x41, 0x41, 0x41, 0x41, 0x41])

#                    # Card Auth X.509
#                    card.read_x509_piv(card.X509.CRD_ATH)
#
#                    # Fingerprint I
#                    card.get_data_piv([0x5F, 0xC1, 0x03])
#
#                   # Fingerprint II 
                    # (6a,82) Not Found
#                    card.get_data_piv([0x5F, 0xC1, 0x04])
#
#                    # Printed Information
                    # (6a,82) Not Found
#                    card.get_data_piv([0x5F, 0xC1, 0x09])
#
#                    # Facial Image
#                    card.get_data_piv([0x5F, 0xC1, 0x08])



#                    card.apdu_select_application(APDU.APPLET.PIV)
#
#                    # Read Security Object
#                    card.get_data_piv([0x5F, 0xC1, 0x06])




#                    card.apdu_select_application(APDU.APPLET.PIV)
##                    card.select_ef([0xdb, 0x00])
##                    card.select_ef([0x30, 0x00])
#                    data, sw1, sw2 = card.get_data_piv([0x5f, 0xc1, 0x06])
#                    print APDU.get_hex(data)


#                    card.apdu_select_application(APDU.APPLET.PIV)
#                    data, sw1, sw2 = card.get_data_piv([0x5f, 0xc1, 0x05])


                    # Input PIN


#            card.apdu_select_application(APPLET.CSG_CCC) #, p1=0x02, p2=0x00)
#            data, sw1, sw2 = card.read_buffer(0, 0, 0x01)
#
#            print "Length: %d" % data[0]
#            card.read_buffer(0, 2, 0x01, read_length=data[0])

#            card.apdu_select_application(APDU.APPLET.CSG_CCC)
#            card.apdu_verify_pin([0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37], p2=0x00)
#            card.select_mf([0x3f, 0x00], p1=0x00, p2=0x00)

#            card.read_card_capability_piv()
#            card.read_chuid()

            # Enter PIN to PIV Applet
#            card.apdu_select_application(APPLET.PIV)
#            card.apdu_verify_pin([0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37], p2=0x80)

#            card.read_card_capability_csg()
#            card.read_card_capability_piv()

#            card.read_card_capability()

#            for j in range(255):
#                card.read_buffer(0, j, 0x01)


#            for i in range(255):
#                for j in range(255):
#                    card.read_buffer(i, j, 0x01)

#
#            card.read_card_capability()

#            card.apdu_verify_pin([0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF], p2=80)

#            card.read_chuid()

#            card.read_printed_info()


#            card.get_data(0x30, 0x00)
#            card.dump_records()
#            visa = VisaCard(connection)
#            if visa is not None:
#                print visa
#                visa.read_visa()

            except smartcard.Exceptions.CardConnectionException as ex:
                print "ERROR: Couldn't connect to card in %s" % reader_list[i]
#                raise



if __name__ == "__main__":
    main()

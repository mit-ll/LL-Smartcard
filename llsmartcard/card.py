# Copyright 2015, MASSACHUSETTS INSTITUTE OF TECHNOLOGY
# Subject to FAR 52.227-11 – Patent Rights – Ownership by the Contractor (May 2014).
# SPDX-License-Identifier: BSD-3-Clause

# Native
import logging
logger = logging.getLogger(__name__)
import struct
import subprocess
import os

# Pysmartcard
from smartcard.sw.ISO7816_4ErrorChecker import ISO7816_4ErrorChecker
from smartcard.sw.ISO7816_8ErrorChecker import ISO7816_8ErrorChecker
from smartcard.sw.ISO7816_9ErrorChecker import ISO7816_9ErrorChecker
from smartcard.sw.ErrorCheckingChain import ErrorCheckingChain
from smartcard.sw.SWExceptions import SWException

# Pydes
import pyDes

# LL Smartcard
import apdu as APDU

class SmartCard:

    # Setup our error chain
    errorchain = []
    errorchain = [ ErrorCheckingChain(errorchain, ISO7816_9ErrorChecker()),
            ErrorCheckingChain(errorchain, ISO7816_8ErrorChecker()),
            ErrorCheckingChain(errorchain, ISO7816_4ErrorChecker()) ]

    def __init__(self, connection, log_level=None):

        self.SECURE_CHANNEL = False
        self.session_keys = None
        if log_level is not None:
            logging.basicConfig(level=log_level)
        self.__conn = connection

    def _log_apdu(self, apdu_data):
        logger.debug("APDU:   " + APDU.get_hex(apdu_data))


    def _log_result(self, data, sw1, sw2):
        logger.debug("RESULT: (%s,%s) %s  (str: %s)" % (hex(sw1),
                                                         hex(sw2),
                                                         APDU.get_hex(data),
                                                         APDU.get_str(data)))
        # See if our status word was an error
        try:
            self.errorchain[0]([], sw1, sw2)
        except SWException, e:
            # Did we get an unsuccessful attempt?
            logger.debug(e)


    def _send_apdu(self, apdu_data):
        """
            Send the proper APDU, depending on what mode we are operating in.
            
            @param apdu_data: RAW APDU data to send
            
            @return: (data, sw1, sw2) 
        """
        if self.SECURE_CHANNEL is False or self.SECURE_CHANNEL == APDU.SECURE_CHANNEL.MODE.NONE:
            return self._send_apdu_raw(apdu_data)
        elif self.SECURE_CHANNEL == APDU.SECURE_CHANNEL.MODE.MAC:
            return self._send_apdu_mac(apdu_data)
        else:
            logger.error("This Secure Channel APDU mode is not currently supported.")


    def _send_apdu_raw(self, apdu_data):
        """
            Send APDU to card and return the data and status words.
            If the result has more data, this will also retrieve the additional 
            data.
            
            @param apdu_data: RAW APDU to send stored in a list
            @return: (data, sw1, sw2)
        """
        # Send the APDU
        self._log_apdu(apdu_data)
        data, sw1, sw2 = self.__conn.transmit(apdu_data)
        self._log_result(data, sw1, sw2)

        # Is there more data in the response?
        while sw1 == APDU.APDU_STATUS.MORE_DATA:
            apdu_get_response = APDU.GET_RESPONSE(sw2)
            self._log_apdu(apdu_get_response)
            data2, sw1, sw2 = self.__conn.transmit(apdu_get_response)
            data += data2
            self._log_result(data2, sw1, sw2)

        # Return our status and data
        return (data, sw1, sw2)

    def _send_apdu_mac(self, apdu_data):
        """
            Send a secure APDU.  This is done by calculating a C-MAC and 
            appending it to the end of the message
            
            IMPORTANT: This will automatically adjust Lc for you!
            
            @param apdu_data: APDU data to send
            @return: data, sw1, sw2
        """
        if self.session_keys is None:
            logger.error("A secure session has not been established.")
            return

        if apdu_data[0] != 0x84:
            logger.warn("Class is not 0x84 in secure message.")
            apdu_data[0] = 0x84


        # Trim Le if needed
        Le = 0x00
        if len(apdu_data) > 5 + apdu_data[4]:
            Le = apdu_data[-1]
            apdu_data = apdu_data[:-1]

        # Increment Lc
        apdu_data[4] = apdu_data[4] + 8


        # Use our MAC key
        mac_key = self.session_keys[APDU.AUTH_KEY_IDX.MAC]

        # Setup our 3-DES MAC instance
        des3_mac = pyDes.triple_des(mac_key, mode=pyDes.CBC,
                                IV="\x00\x00\x00\x00\x00\x00\x00\x00")

        # Add padding and pack it up for pyDes
        apdu_extern_auth_packed = [struct.pack('B', x) for x in self._pad_plaintext(apdu_data)]

        c_mac = des3_mac.encrypt(apdu_extern_auth_packed)[-8:]
        c_mac = list(struct.unpack('%dB' % len(c_mac), c_mac))

        logger.debug("C-MAC: %s" % APDU.get_hex(c_mac))

        # Append MAC to APDU
        apdu_data += c_mac + [Le]

        # Send appended APDU
        return self._send_apdu_raw(apdu_data)


    def _report_error(self, sw1, sw2, error):
        """ Print Error """
        # @todo: Figure out the SW1 SW2 meaning

        print "ERROR (%s,%s): %s" % (hex(sw1), hex(sw2), error)


    def _generate_random(self, length):
        """
            Generate a list of random bytes
            @param length: Number of bytes to generate
            @return: List of random bytes
        """
        rtn = []
        for i in range(length):
            rtn.append(ord(os.urandom(1)))

        return rtn


    def _pad_plaintext(self, plaintext):
            """
                Pad out any plaintext to be fed into MAC functions
                
                @param plaintext: plaintext to pad
                @return: a copy of plaintext with padding appended
            """
            # ensure the plaintext is divisible by 8 and that at least some padding is added
            pad = False
            plaintext = list(plaintext)
            while len(plaintext) % 8 != 0 or not pad:
                if pad:
                    plaintext.append(0x00)
                else:
                    plaintext.append(0x80)
                    pad = True

            return plaintext


    def _str_privs(self, privs):
        """
        
        """
        out = []
        if 0b10000000 & privs:
            out.append("Security Domain")
        if 0b01000000 & privs:
            out.append("DAP DES Verification")
        if 0b00100000 & privs:
            out.append("RFU")
        if 0b00010000 & privs:
            out.append("Card Manager Lock Privilege")
        if 0b00001000 & privs:
            out.append("Card Terminate Privilege")
        if 0b00000100 & privs:
            out.append("Default Selected Applet")
        if 0b00000010 & privs:
            out.append("PIN Change")
        if 0b00000001 & privs:
            out.append("RFU")

        return out


    def _print_gp_registry_data(self, input_data):
        """
            Decode Applicaiton Data
            Reference: GP 2.1.1 / page 115
        """
        offset = 0
        while offset < len(input_data):
            t = input_data[offset]
            if t == 0x9F and input_data[offset + 1] == 0x70:
                t = 0x9f70
                offset += 1
            length = input_data[offset + 1]
            value = input_data[offset + 2:offset + 2 + length]

            if t == 0x4f:
                print "AID: %s" % APDU.get_hex(value)
            elif t == 0x9f70:
                print "  Life Cycle State: %08s" % '{0:08b}'.format(value[0])
            elif t == 0xc5:
                print "  Application Privleges: %s %s" % (APDU.get_hex(value),
                                                        self._str_privs(value[0]))
            elif t == 0x84:
                print "  Executable Module ID: %s" % (APDU.get_hex(value))
            else:
                print "  UNKNOWN: t:%s, l:%s, v:%s" % (hex(t), hex(length),
                                                     APDU.get_hex(value))

            offset += length + 2


    def apdu_select_application(self, application_id, pix=[], p1=0x04, p2=0x00):
        """
            Send APDU to select a Java Applet and return results
            
            @param application_id: The AID of the application on the card in a list
            @return: (data, sw1, sw2) 
        """
        apdu_select = APDU.SELECT(application_id + pix, P1=p1, P2=p2)

        data, sw1, sw2 = self._send_apdu(apdu_select)

        if sw1 != APDU.APDU_STATUS.SUCCESS:
            print "ERROR (%s,%s): SELECT failed." % (hex(sw1), hex(sw2))

        return (data, sw1, sw2)


    def apdu_select_object(self, object_id, p1=0x02, p2=0x00):
        """
            Send APDU to select a Java Applet and return results
            
            @param object_id: The OID of the object on the card in a list
            @return: (data, sw1, sw2) 
        """
        apdu_select = APDU.SELECT(object_id, P1=p1, P2=p2)

        data, sw1, sw2 = self._send_apdu(apdu_select)

        if sw1 != APDU.APDU_STATUS.SUCCESS:
            print "ERROR (%s,%s): SELECT failed." % (hex(sw1), hex(sw2))

        return (data, sw1, sw2)


    def apdu_select_df(self, file_id, p1=0x01, p2=0x00):
        """
            Send APDU to select a Directory File (Within master file)
            
            @param file_id: 2 byte file ID to select
            @param p2: 0x00 or 0x0c
            @return: (data, sw1, sw2) 
        """
        apdu_select = APDU.SELECT(file_id, P1=p1, P2=p2)

        data, sw1, sw2 = self._send_apdu(apdu_select)

        if sw1 != APDU.APDU_STATUS.SUCCESS:
            print "ERROR (%s,%s): SELECT failed." % (hex(sw1), hex(sw2))

        return (data, sw1, sw2)


    def apdu_select_ef(self, file_id, p1=0x02, p2=0x00):
        """
            Send APDU to select a Elementary File (or Object)
            
            @param file_id: 2 byte file ID to select
            @param p2: 0x00 or 0x0c
            @return: (data, sw1, sw2) 
        """
        apdu_select = APDU.SELECT(file_id, P1=p1, P2=p2)

        data, sw1, sw2 = self._send_apdu(apdu_select)

        if sw1 != APDU.APDU_STATUS.SUCCESS:
            print "ERROR (%s,%s): SELECT failed." % (hex(sw1), hex(sw2))

        return (data, sw1, sw2)


    def apdu_select_mf(self, file_id, p1=0x03, p2=0x00):
        """
            Send APDU to select a Master File
            
            @param file_id: 2 byte file ID to select
            @param p2: 0x00 or 0x0c
            @return: (data, sw1, sw2) 
        """
        # @todo: Try all classes
        apdu_select = APDU.SELECT(file_id, CLA=0x80, P1=p1, P2=p2)

        data, sw1, sw2 = self._send_apdu(apdu_select)

        if sw1 != APDU.APDU_STATUS.SUCCESS:
            print "ERROR (%s,%s): SELECT failed." % (hex(sw1), hex(sw2))

        return (data, sw1, sw2)


    def apdu_get_data(self, address):
        """
            Send APDU to get data and return results
            
            @param p1: high order byte
            @param p2: low order byte
            @return: (data, sw1, sw2) 
        """
        p1 = address[0]
        p2 = address[1]
        apdu_get_data = APDU.GET_DATA(p1, p2)
        data, sw1, sw2 = self._send_apdu(apdu_get_data)

        if sw1 == APDU.APDU_STATUS.WRONG_LENGTH:
            apdu_get_data2 = APDU.GET_DATA(p1, p2, Lc=sw2)
            return self._send_apdu(apdu_get_data2)

        return (data, sw1, sw2)


    def apdu_read_record(self, p1, p2, cla=0x00):
        """
            Send APDU to get data and return results
            
            Reference: GP 2.1.1 / D.4.1
            
            @param p1: high order byte
            @param p2: low order byte
            @return: (data, sw1, sw2) 
        """
        apdu_read_record = APDU.READ_RECORD(p1, p2, CLA=cla)

        data, sw1, sw2 = self._send_apdu(apdu_read_record)

        if sw1 == APDU.APDU_STATUS.WRONG_LENGTH:
            apdu_read_record2 = APDU.READ_RECORD(p1, p2, CLA=cla, Le=sw2)
            data, sw1, sw2 = self._send_apdu(apdu_read_record2)
        return (data, sw1, sw2)


    def apdu_init_update(self, p1, p2, challenge=None):
        """
            Send Initialize Update APDU to initialize a new secure channel.
            
            @param p1: Key version number (Default: 0)
            @param p2: Key identifier (Default: 0)
            @param challenge: 8 byte random number
        """
        # Generate a new random number?
        if challenge is None:
            challenge = self._generate_random(8)

        apdu_init_update = APDU.INIT_UPDATE(p1, p2, challenge)

        data, sw1, sw2 = self._send_apdu(apdu_init_update)

        return (data, sw1, sw2)


    def print_applications(self):
        """
            Once a secure channel is opened, list all Applications on the card.
        """
        for domain in [0x80, 0x40, 0x20, 0x10]:

            # Get Next
            apdu = APDU.GET_STATUS(domain, 0x02, APDU.SEARCH_CRITERIA.AID)
            data, sw1, sw2 = self._send_apdu(apdu)
            offset = 0
            while offset < len(data):
                t = data[offset]
                length = data[offset + 1]
                value = data[offset + 2:offset + 2 + length]
                if t == 0xE3:
                    self._print_gp_registry_data(value)
                else:
                    logger.error("Invalid data returned.")
                offset += length + 2


        return (data, sw1, sw2)


    def apdu_get_status(self, p1, p2, search_criteria):
        """
            Send Get Status APDU
        
            @param P1:  80 - Issuer Security Domain
                        40 - Application Security Domain
                        20 - Executable Load Files only
                        10 - Executable Load Files and their Executable Modules only
            @param P2:  0bx0 - get all/first occurrence(s)
                        0bx1 - get next
                        0b0x - Response Structure 1
                        0b1x - Response Structure 2
            @param search_criteria: 4f00 used to indicated AID
        
        """
        apdu = APDU.GET_STATUS(p1, p2, search_criteria)
        data, sw1, sw2 = self._send_apdu(apdu)
        return (data, sw1, sw2)


    def apdu_authenticate(self, card_challenge, rand_challenge, cryptogram,
                          security_level=APDU.SECURE_CHANNEL.MODE.NONE):
        """
            Given both of our Nonces, send back our authentication apdu
            
            @param card_challege: Nonce from card
            @param rand_challege: Nonce generated by host
            @param cryptogram: Cryptogram sent by card
            @return: data, sw1, sw2
        """

        if self.session_keys is None:
            logger.error("Secure Channel hasn't be opened yet.")
            return

        # Get ready for authentication
        auth_key = self.session_keys[APDU.AUTH_KEY_IDX.AUTH]

        # Setup our 3-DES MAC instance
        des3_auth = pyDes.triple_des(auth_key, mode=pyDes.CBC,
                                IV="\x00\x00\x00\x00\x00\x00\x00\x00")

        #
        # Validate our cryptogram
        #
        # Generate our plaintext
        card_cryptogram_plaintext = rand_challenge + card_challenge
        # Pad appropriately
        card_cryptogram_plaintext = self._pad_plaintext(card_cryptogram_plaintext)
        # Pack up for pyDes
        card_cryptogram_plaintext = [struct.pack('B', x) for x in card_cryptogram_plaintext]

        # Generate our cryptogram
        cryptogram_host_ciphertext = des3_auth.encrypt(card_cryptogram_plaintext)
        cryptogram_host_mac = cryptogram_host_ciphertext[-8:]
        cryptogram_host = struct.unpack('%dB' % len(cryptogram_host_mac), cryptogram_host_mac)
        cryptogram_host = list(cryptogram_host)

        # Check our cryptogram
        if cryptogram_host != cryptogram:
            logger.error("Cryptogram Invalid for this card!")
            return False

        #
        # Generate our authentication response
        #
        # Generate Plaintext
        card_auth_plaintext = card_challenge + rand_challenge

        # Pad appropriately
        card_auth_plaintext = self._pad_plaintext(card_auth_plaintext)

        # Pack up for pyDes
        card_auth_plaintext = [struct.pack('B', x) for x in card_auth_plaintext]

        # Generate our authentication response
        auth_host_ciphertext = des3_auth.encrypt(card_auth_plaintext)[-8:]
        auth_cryptogram = list(struct.unpack('%dB' % len(auth_host_ciphertext), auth_host_ciphertext))

        logger.debug("Authentication Cryptogram: %s" % APDU.get_hex(auth_cryptogram))

        # Generate our C-MAC for the response
        apdu_extern_auth = APDU.EXTERNAL_AUTHENTICATE(security_level,
                                                      auth_cryptogram, [])

        # Send the APDU in C-MAC mode
        return self._send_apdu_mac(apdu_extern_auth)


    def open_secure_channel(self, aid, keys,
                            security_level=APDU.SECURE_CHANNEL.MODE.NONE):
        """
            Open secure channel to allow security functions
            
            @param keys: Keys to use for this channel
            @return: True/False
        """
        self.keys = keys

        #
        # Define some supplementary functions
        # 
        def fill_data(diversify_data, idx, diver_type=APDU.SECURE_CHANNEL.DIVERSIFY.VISA2):
            """
                Given the diversity data from the card and the index for the key
                 to be generated, this will fill out the data appropriately to
                 generate a diversified key
                 
                 @param diversify_data: diversity data from the card
                 @param idx: key index to generate the plaintext for
                 @diver_type: Type of diversification, VISA2 or default
            """
            data = []
            if diver_type == APDU.SECURE_CHANNEL.DIVERSIFY.VISA2:
                # VISA2
                data.append(diversify_data[0])
                data.append(diversify_data[1])
                data.append(diversify_data[4])
                data.append(diversify_data[5])
                data.append(diversify_data[6])
                data.append(diversify_data[7])
                data.append(0xF0)
                data.append(idx)
                data.append(diversify_data[0])
                data.append(diversify_data[1])
                data.append(diversify_data[4])
                data.append(diversify_data[5])
                data.append(diversify_data[6])
                data.append(diversify_data[7])
                data.append(0x0F)
                data.append(idx)

            elif diver_type is None:
                # EMV
                data.append(diversify_data[4])
                data.append(diversify_data[5])
                data.append(diversify_data[6])
                data.append(diversify_data[7])
                data.append(diversify_data[8])
                data.append(diversify_data[9])
                data.append(0xF0)
                data.append(idx)
                data.append(diversify_data[4])
                data.append(diversify_data[5])
                data.append(diversify_data[6])
                data.append(diversify_data[7])
                data.append(diversify_data[8])
                data.append(diversify_data[9])
                data.append(0x0F)
                data.append(idx)
            else:
                return None

            return data


        def get_diversified_keys(keys, diversify_data, diver_type=APDU.SECURE_CHANNEL.DIVERSIFY.VISA2):
            """
                Given the keys and diversity data from the card, generate the 
                diversified keys.
                
                @param keys: keys to be diversified
                @param diversify_data: Diversity data from the card
                @param diver_type: VISA or default
                @return: List of diversified keys 
            """

            logger.debug("Diversifying keys...")

            # Diversify each key
            for i in range(len(keys)):
                # Get the data to encrypt
                data = fill_data(diversify_data, i + 1, diver_type)

                logger.debug("data: %s" % data)
                logger.debug("key: %s" % keys[i])

                # Unpack in the form that pyDes Expects
                data = [struct.pack('B', x) for x in data]

                # Encrypt data to get new key
                des3 = pyDes.triple_des(keys[i])
                keys[i] = des3.encrypt(data)

            return keys

        def get_session_keys(keys, rand_challenge, card_challenge):
            """
                Derive the session keys using the two nonces and the input keys
                
                @param keys: Keys to use for this session
                @param rand_challenge: Nonce sent from host
                @para card_challenge: Nonce sent from card
                
                @return: list of session keys
            """
            derivation_data = card_challenge[4:] + \
                        rand_challenge[0:4] + \
                        card_challenge[0:4] + \
                        rand_challenge[4:]

            logger.debug("Deriving session keys..")
            logger.debug("derivData: %s" % derivation_data)

            # Unpack in the form that pyDes Expects
            derivation_data = [struct.pack('B', x) for x in derivation_data]

            session_keys = []

            for i in range(len(keys) - 1):
                # Pack in the form that pyDes Expects
                des3 = pyDes.triple_des(keys[i])
                session_key = des3.encrypt(derivation_data)

#                session_key = struct.unpack('%dB' % len(session_key), session_key)

                session_keys.append(session_key)


            # The last key remains the same
            session_keys.append(keys[2])

            logger.debug("Session keys: %s" % session_keys)

            return session_keys


        #
        #    Begin actual function
        #
        logger.debug("Opening secure channel...")

        # Save our keys
        self.keys = []
        for k in keys:
            self.keys.append([struct.pack('B', x) for x in k])

        # Generate an 8 byte nonce
        rand_challenge = self._generate_random(8)

        # Initialize our authentication
        (data, sw1, sw2) = self.apdu_init_update(0, 0, challenge=rand_challenge)

        # Override results for debugging?
#        rand_challenge = [0xA6, 0x1E, 0xF6, 0x6D, 0x6A, 0x27, 0x0E, 0x9A]
#        data = [0x00, 0x00, 0x21, 0x80, 0x88, 0x10, 0x0B, 0x15, 0x20, 0xCB, 0x01, 0x01, 0x23, 0xCC, 0x76, 0xF2, 0xB2, 0x88, 0x01, 0x73, 0x07, 0xAD, 0xEF, 0xAD, 0x97, 0xAA, 0xFC, 0x0B, 0x90, 0x00]

        if (sw1, sw2) != APDU.STATUS_WORDS.SUCCESS:
            logger.error("INIT UPDATE failed.")
            return

        # Extract the parameters from our data
        key_diversification_data = data[0:10]
        key_info = data[10:12]
        card_challenge = data[12:20]
        cryptogram_card = data[20:28]

        # Log some stuff
        logger.debug("Key Diversification: %s" % APDU.get_hex(key_diversification_data))
        logger.debug("Key Info: %s" % APDU.get_hex(key_info))
        logger.debug("Card Challenge: %s" % APDU.get_hex(card_challenge))
        logger.debug("Card Cryptogram: %s" % APDU.get_hex(cryptogram_card))

        # Diversify our keys
        diversified_keys = get_diversified_keys(self.keys, key_diversification_data)

        # Derive session keys
        self.session_keys = get_session_keys(diversified_keys, rand_challenge, card_challenge)

        # Authenticate to the card
        self.apdu_authenticate(card_challenge, rand_challenge, cryptogram_card,
                               security_level=security_level)

        logger.debug("Secure Channel Opened!")

        self.SECURE_CHANNEL = security_level


    def apdu_verify_pin(self, pin, location, pad_pin=8):
        """
            Send a VERIFY PIN for smartcard
            
            @param pin: pin to enter
            @param location: location of pin (1 byte)
            @param pad_pin: Number of bytes to pad pin to (padding is 0xff)
        """
        # Do we need to pad the pin?
        while len(pin) < pad_pin:
            pin.append(0xff)

        apdu = APDU.VERIFY_PIN(location, pin)

        data, sw1, sw2 = self._send_apdu(apdu)

        if sw1 != APDU.APDU_STATUS.SUCCESS:
            print "ERROR (%s,%s): VERIFY PIN failed." % (hex(sw1), hex(sw2))
            if sw1 == 0x63 and sw2 & 0xc0 == 0xc0:
                print "WARNING: %d tries remaining!" % (sw2 & 0x0F)
        else:
            print "* Key Authentication Successful!"
        return (data, sw1, sw2)


    def apdu_change_reference_data(self, location, old_pin, new_pin,
                                   pad_pin=8, first=False):
        """
            Change the reference data on the card, e.g. PIN
            
            @param location:    0x00 - Global, 
                                0x80 - Application, 
                                0x81, Application PUK
            @param old_pin: Existing PIN
            @param new_pin: New PIN
            @param pad_pin: How many bytes should the PIN be?
            @param first: Is this the first time setting the PIN?
            
            @return (data, sw1, sw2) 
        """
        # Do we need to pad the pin?
        while len(new_pin) < pad_pin:
            new_pin.append(0xff)
        while len(old_pin) < pad_pin:
            old_pin.append(0xff)

        if first:
            P1 = 0x01
            old_pin = []
        else:
            P1 = 0x00
        P2 = location

        apdu = APDU.CHANGE_REFERENCE_DATA(P1, P2, old_pin, new_pin)

        data, sw1, sw2 = self._send_apdu(apdu)

        return (data, sw1, sw2)


    def apdu_reset_retry_counter(self, puk, location, new_pin, pad_pin=8):
        """
            Reset the retry counter using the PUK
        """

        # Do we need to pad the pin?
        if puk is not None:
            while len(puk) < pad_pin:
                puk.append(0xff)

        if new_pin is not None:
            while len(new_pin) < pad_pin:
                new_pin.append(0xff)

        # This is according to the ISO spec, but doesn't seem to work
        if new_pin is None and puk is None:
            P1 = 0x03
        elif new_pin is None:
            P1 = 0x01
        elif puk is None:
            P1 = 0x02
        else:
            P1 = 0x00

        if self.SECURE_CHANNEL is False:
            P1 = 0x00
        else:
            P1 = 0x00


        apdu = APDU.RESET_RETRY_COUNT(P1, location, puk, new_pin, CLA=0x00)

        data, sw1, sw2 = self._send_apdu(apdu)

        if sw1 != APDU.APDU_STATUS.SUCCESS:
            print "ERROR (%s,%s): VERIFY PIN failed." % (hex(sw1), hex(sw2))
            if sw1 == 0x63 and sw2 & 0xc0 == 0xc0:
                print "WARNING: %d tries remaining!" % (sw2 & 0x0F)
        else:
            print "* PIN retry has been reset."
        return (data, sw1, sw2)


    def apdu_set_status(self, status_type, status_state, aid=[]):
        """    
            Set the status of an application on the smartcard
        """

        apdu = APDU.SET_STATUS(status_type, status_state, aid)

        return self._send_apdu(apdu)



    def dump_records(self):
        for sfi in range(32):
            for rec in range (17):
                logger.debug("REC %d SFI %d" % (rec, (sfi << 3) | 4))
                data, sw1, sw2 = self.apdu_read_record(rec, (sfi << 3) | 4)
                if sw1 == APDU.APDU_STATUS.SUCCESS:
                    print "REC %d SFI %d" % (rec, (sfi << 3) | 4)
                    print "Hex: %s" % APDU.get_hex(data)
                    print "Str: %s" % APDU.get_str(data)
                    
    
    def _decode_bcd(self, bcd_num):
        """
            Given a 5 bit Binary Coded Decimal, decode back to the appropriate string
            
            @param bcd_num : 5 bit Binary Coded Decimal number
            @return: Character represenation
        """
        bcd_table = {'0':0b00001,
                     '1':0b10000,
                     '2':0b01000,
                     '3':0b11001,
                     '4':0b00100,
                     '5':0b10101,
                     '6':0b01101,
                     '7':0b11100,
                     '8':0b00010,
                     '9':0b10011,
                     'SS':0b11010,
                     'FS':0b10110,
                     'ES':0b11111}
        for char in bcd_table:
            if bcd_table[char] == bcd_num:
                return char

        return None


    def _get_ber_tlv(self, data, offset=0):
        """
            Get the next BER-TLV value from data
            
            @param data: Data encoded with BER-TLV 
            @param offset: Offset into data buffer
            @return: [type, length, value, next_tlv]
        """

        tlv_type = data[offset]

        if data[offset + 1] == 0x81:
            tlv_length = data[offset + 2]
            tlv_value = data[offset + 3:offset + 3 + tlv_length]
            next_tlv = tlv_length + 3

        elif data[offset + 1] == 0x82:
            tlv_length = data[offset + 2] << 8 | data[offset + 3]
            tlv_value = data[offset + 4:offset + 4 + tlv_length]
            next_tlv = tlv_length + 4

        else:
            tlv_length = data[offset + 1]
            tlv_value = data[offset + 2:offset + 2 + tlv_length]
            next_tlv = tlv_length + 2

        return [tlv_type, tlv_value, next_tlv]


    def _decode_ber_tlv(self, data):
        """
            Read BER-TLV data and return list of [type, data] pairs
            
            Ref: CAC Endpoint Implementation Guide v1
            
            @param data:
            @return: list of [type, data] pairs 
        """
        offset = 0

        rtn_list = []
        while offset < len(data):
            # Get Data
            tlv_type, tlv_value, next_tlv = self._get_ber_tlv(data, offset)
            # Update pointer into buffer
            offset += next_tlv
            # append to our results
            rtn_list.append([tlv_type, tlv_value])

        # If its tag type 0x53, just return the data
        tlv = self._get_ber_tlv(data)
        if tlv[0] == 0x53:
            data = tlv[1]
            return self._decode_ber_tlv(data)
        else:
            return rtn_list


class CAC(SmartCard):
    """
        This class implements some knwown functionality for the DoD CAC smartcard.
    """

    def _lookup_agency(self, code):
        """
            Converts agency code string in CHUID to the actual name of the agency
            
            ref: http://csrc.nist.gov/publications/nistpubs/800-87-Rev1/SP800-87_Rev1-April2008Final.pdf
            
            @param code: String code of Agency
            @return: String name of Agency or Uknown
        """
        agency_table = {'9700':'DEFENSE, Department of (except military departments)',
                        '5700':'AIR FORCE, Department of the (Headquarters, USAF) '}
        if code in agency_table:
            return agency_table[code]
        else:
            return "Unknown (See: SP800-87)"


    def _lookup_oc(self, code):
        """
            Convert organization code in CHUID to name of organization
            
            @param code: character code of organization
            @return: Name of organization
        """
        table = {'1':'Federal Government Agency',
                    '2':'State Government Agency',
                    '3':'Commercial Enterprise',
                    '4':'Foreign Government'}
        if code in table:
            return "%s (%s)" % (table[code], int(code))
        else:
            return "Unknown (See: SP800-87)"

    def _lookup_poa(self, code):
        """
            Convert Personal Association Category code in CHUID to string name
            
            @param code: Character poa code
            @return: String of association
        """
        table = {'1': 'Employee',
                     '2': 'Civil',
                     '3': 'Executive Staff',
                     '4': 'Uniformed Service',
                     '5': 'Contractor',
                     '6': 'Organizational Affiliate',
                     '7': 'Organizational Beneficiary'}
        if code in table:
            return "%s (%s)" % (table[code], int(code))
        else:
            return "%s (See: (See: SP800-87)" % hex(code)


    def _lookup_card_app_type(self, code):
        """
            Lookup Card Application Type from CardURL
            
            @param code: Byte encoding app type
            @return: Application type
        """
        table = {0x01: 'genericContainer',
                 0x02: 'ski',
                 0x04: 'ski'}
        if code in table:
            return "%s (%s)" % (table[code], hex(code))
        else:
            return "%s (See: GSC-IS 7-1)" % hex(code)


    def _lookup_card_object_id(self, code):
        """
            Lookup Card Object ID from CardURL
            
            @param code: Byte encoding object ID
            @return: Object Name
        """
        code = code[0] << 8 | code[1]
        table = {   0x2000:'generalInfo',
                    0x2100:'proPersonalInfo',
                    0x3000:'accessControl',
                    0x4000:'login',
                    0x5000:'cardInfo',
                    0x6000:'biometrics',
                    0x7000:'digitalSigCert',
                    #      -- CAC data model definitions
                    0x0200:'personInstance',
                    0x0202:'benefitsInfo',
                    0x0203:'otherBenefits',
                    0x0201:'personnel',
                    0x0300:'loginInfo',
                    0x02FE:'pkiCert',
                    #      -- Common definitions
                    0x0007:'SEIWG'}
        if code in table:
            return "%s (%s)" % (table[code], hex(code))
        else:
            return "%s (See: GSC-IS 7-1)" % hex(code)

    def _lookup_key_crypto(self, code):
        """
            Lookup Key Crypto Algorithm from CardURL
            
            @param code: Byte encoding of Key Crypto Algorithm
            @return: Crypto Algorithm
        """
        table = {   0x00:'DES3-16-ECB',
                    0x01:'DES3-16-CBC',
                    0x02:'DES-ECB',
                    0x03:'DES-CBC',
                    0x04:'RSA512',
                    0x05:'RSA768',
                    0x06:'RSA1024',
                    0x07:'RSA2048',
                    0x08:'AES128-ECB',
                    0x09:'AES128-CBC',
                    0x0a:'AES192-ECB',
                    0x0b:'AES192-CBC',
                    0x0c:'AES256-ECB',
                    0x0d:'AES256-CBC'}
        if code in table:
            return "%s (%s)" % (table[code], hex(code))
        else:
            return "%s (See: GSC-IS 7-1)" % hex(code)

    def _lookup_card_type(self, code):
        """
            Lookup Card Type
            
            @param code: Byte encoding of Key Crypto Algorithm
            @return: Crypto Algorithm
        """
        table = {   0x01:'File System',
                    0x02:'Java Card'
                    }
        if code in table:
            return "%s (%s)" % (table[code], hex(code))
        else:
            return "%s (See: CAC End-Point Impelementation Guide)" % hex(code)


    def _lookup_cert(self, registered_id, object_id):
        """
            Lookup the name of the certificate given its RID and OID
            
            @param registered_id: RID of cert in question
            @param object_id: Object ID of cert in question
            @return: Name of the cert being references
        """

        table = {   APDU.get_hex(APDU.OBJ_NIST_PIV.KEY_CRD_ATH):'Card Authentication (NIST)',
                    APDU.get_hex(APDU.OBJ_NIST_PIV.KEY_DIG_SIG):'Digital Signature (NIST)',
                    APDU.get_hex(APDU.OBJ_NIST_PIV.KEY_MNG):'Key Management (NIST)',
                    APDU.get_hex(APDU.OBJ_NIST_PIV.KEY_PIV_ATH):'PIV Authentication (NIST)',
                    APDU.get_hex(APDU.OBJ_DOD_CAC.KEY_PKI_ENC):'Encryption (CaC)',
                    APDU.get_hex(APDU.OBJ_DOD_CAC.KEY_PKI_ID):'Identification (CaC)',
                    APDU.get_hex(APDU.OBJ_DOD_CAC.KEY_PKI_SIG):'Signature (CaC'}

        object_id = APDU.get_hex(object_id)
        if object_id in table:
            return "%s (%s)" % (table[object_id], object_id)
        else:
            return "Unknown (%s)" % object_id


    def _splash(self, string):
        """ Used to keep output pretty """
        print "--------------------- %s ---------------------" % string


    def _print_fasc_n(self, data):
        """
            Will print the FASC-N in human-readable form
            
            @param data: 25 byte bytestring containting FASC-N
        """
        # Frist combine into 1 binary string
        fasc_n = 0
        for i in range(len(data)):
            fasc_n = fasc_n << 8 | data[i]

        # Now break out the 5 bit individual numbers
        fasc_n_list = []
        for i in reversed(range(40)):
            mask = 0b11111 << i * 5
            bcd_num = (fasc_n & mask) >> i * 5
            # Decode and validate parity bits
            fasc_n_list.append(self._decode_bcd(bcd_num))

        # Extract all of the fields
        agency_code = "".join(fasc_n_list[1:5])
        system_code = "".join(fasc_n_list[6:10])
        credential_number = "".join(fasc_n_list[11:17])
        cs = fasc_n_list[18]
        ici = fasc_n_list[20]
        pi = "".join(fasc_n_list[22:32])
        oc = fasc_n_list[32]
        oi = "".join(fasc_n_list[33:37])
        poa = fasc_n_list[37]

        # print in nice format
        print "  FASC-N (SEIWG-012): %s" % hex(fasc_n)
        print "   Agency Code: %s / %s" % (agency_code, self._lookup_agency(agency_code))
        print "   System Code: %s" % system_code
        print "   Credential Number: %s" % credential_number
        print "   Credential Series: %s" % cs
        print "   Individual Credential Issue: %s" % ici
        print "   Person Identifier: %s" % pi
        print "   Organizational Category: %s / %s" % (oc, self._lookup_oc(oc))
        print "   Organizational Identifier: %s / %s" % (oi, self._lookup_agency(oi))
        print "   Person Association Category: %s / %s" % (poa, self._lookup_poa(poa))


    def _print_ccc(self, tv_data, applet=None, object_id=None):
        """
            Prints Card Capability Container
            
            Ref: SP800-73-1
            Ref: GSC-IS / Page 6-5
            
            @param tv_data: Type/Value data returned from a read_object call
        """

        # Print results to terminal
        self._splash("CCC (%s)" % APDU.get_hex(applet))
        # Loop over type/value pairs
        for tv in tv_data:
            tlv_type = tv[0]
            tlv_value = tv[1]
            if tlv_type == 0xf0:
                print "   Card Identifier [%s]" % APDU.get_hex(tlv_value)
                print "    GSC-RID: %s" % APDU.get_hex(tlv_value[0:5])
                print "    Manufacturer ID: %s" % hex(tlv_value[5])
                print "    Card Type: %s" % self._lookup_card_type(tlv_value[6])
                print "    Card ID: %s | %s" % (APDU.get_hex(tlv_value[7:17]),
                                                APDU.get_hex(tlv_value[17:22]))
            elif tlv_type == 0xf1:
                print "   Capability Container version number: %s" % APDU.get_hex(tlv_value)
            elif tlv_type == 0xf2:
                print "   Capability Grammar version number: %s" % APDU.get_hex(tlv_value)
            elif tlv_type == 0xf3:
                print "   Applications CardURL [%s]" % APDU.get_hex(tlv_value)
                print "     RID: %s" % APDU.get_hex(tlv_value[0:5])
                print "     Application Type: %s" % self._lookup_card_app_type(tlv_value[5])
                print "     Object ID: %s" % self._lookup_card_object_id(tlv_value[6:8])
                print "     Application ID: %s" % APDU.get_hex(tlv_value[8:10])
                print "     AccProfile: %s" % hex(tlv_value[10])
                print "     PIN ID: %s" % hex(tlv_value[11])
                print "     AccKey Info: %s" % APDU.get_hex(tlv_value[12:16])
                print "     -- Alternate ---"
                print "      PIN ID: %s" % hex(tlv_value[8])
                print "       Key File ID: %s" % APDU.get_hex(tlv_value[9:11])
                print "       Key Number: %s" % hex(tlv_value[11])
                print "       Key Algorithm: %s" % self._lookup_key_crypto(tlv_value[12])
                print "      Key Algorithm: %s" % self._lookup_key_crypto(tlv_value[13])

            elif tlv_type == 0xf4:
                print "   PKCS#15: %s" % APDU.get_hex(tlv_value)
            elif tlv_type == 0xf5:
                print "   Registered Data Model number: %s" % APDU.get_hex(tlv_value)
            elif tlv_type == 0xf6:
                print "   Access Control Rule Table: %s" % APDU.get_hex(tlv_value)
            elif tlv_type == 0xf7:
                print "   CARD APDUs: %s" % APDU.get_hex(tlv_value)
            elif tlv_type == 0xfa:
                print "   Redirection Tag: %s" % APDU.get_hex(tlv_value)
            elif tlv_type == 0xfb:
                print "   Capability Tuples (CTs): %s" % APDU.get_hex(tlv_value)
            elif tlv_type == 0xfc:
                print "   Status Tuples (STs): %s" % APDU.get_hex(tlv_value)
            elif tlv_type == 0xfd:
                print "   Next CCC: %s" % APDU.get_hex(tlv_value)
            elif tlv_type == 0xfe:
                print "   Error Detection Code: %s" % APDU.get_hex(tlv_value)
            else:
                print "  [TLV] Type: %s, Length: %d  " % (hex(tlv_type), len(tlv_value))

        self._splash("CCC (%s)" % APDU.get_hex(applet))


    def _print_chuid(self, tv_data, applet=None, object_id=None):
        """
            Will take CHUID data and print extracted information
            
            Reference:
                http://fips201ep.cio.gov/documents/TIG_SCEPACS_v2.2.pdf (Page 9)
                http://csrc.nist.gov/publications/nistpubs/800-73-3/sp800-73-3_PART1_piv-card-applic-namespace-date-model-rep.pdf (Page 5)
                
            @param tv_data: Type/Value data returned from a read_object call
        """
        # Print results to terminal
        self._splash("CHUID (%s)" % APDU.get_hex(applet))
        # Loop over extracted data and print nicely formatted
        for tv in tv_data:
            tlv_type = tv[0]
            tlv_value = tv[1]

            if tlv_type == 0x30:
                self._print_fasc_n(tlv_value)
                print ""
            elif tlv_type == 0x31:
                print "  Agency Code: %s" % APDU.get_hex(tlv_value)
            elif tlv_type == 0x34:
                print "  GUID: %s" % APDU.get_hex(tlv_value)
            elif tlv_type == 0x35:
                print "  Expiration Date (YYYYMMDD): %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x3E:
                print "  Asymmetric Signature: [length: %d]" % len(tlv_value)
            elif tlv_type == 0xFE:
                print "Error Detection Code Found."
            else:
                print "  [TLV] Type: %s, Length: %d  " % (hex(tlv_type),
                                                            len(tlv_value))

        self._splash("CHUID (%s)" % APDU.get_hex(applet))


    def _print_x509_cert(self, tv_data, registered_id, object_id):
        """
            Read and decode the X.509 Certificate for PIV Authentication
            
            X.509 Certificate for PIV Authentication    5FC105  M
            X.509 Certificate for Digital Signature     5FC10A  O
            X.509 Certificate for Key Management        5FC10B  O
            X.509 Certificate for Card Authentication   5FC101  O
            
            Ref: SP80-73-1 / Appendix A
            
            @param cert_address: Address of certificate to read 
        """

        cert_name = self._lookup_cert(registered_id, object_id)



        self._splash("X.509 %s Certificate (%s)" % (cert_name, APDU.get_hex(registered_id)))

        # Loop over extracted data and print nicely formatted
        for tv in tv_data:
            tlv_type = tv[0]
            tlv_value = tv[1]

            if tlv_type == 0x70:
                print "Certificate: [length: %d]" % len(tlv_value)
            elif tlv_type == 0x71:
                print "Certificate Info: %s" % APDU.get_hex(tlv_value)
            elif tlv_type == 0x72:
                print "MSCUID: %s" % APDU.get_hex(tlv_value)
            elif tlv_type == 0xFE:
                print "Error Detction Code Found."
            else:
                print "[TLV] %s : %s : %s" % (hex(tlv_type),
                                        len(tlv_value),
                                        APDU.get_hex(tlv_value))

        self._splash("X.509 %s Certificate (%s)" % (cert_name, APDU.get_hex(registered_id)))


    def _print_sec_obj(self, tv_data, registered_id, object_id):
        """
            Print the Security Object (Ref: SP800-73-1)
        """
        self._splash("Security Object (%s)" % (APDU.get_hex(object_id)))

        # Loop over extracted data and print nicely formatted
        for tv in tv_data:
            tlv_type = tv[0]
            tlv_value = tv[1]

            if tlv_type == 0xBA:
                print "Mapping of DG to ContainerID: %s" % APDU.get_hex(tlv_value)
            elif tlv_type == 0xBB:
                print "Security Object: [length: %d]" % len(tlv_value)
            elif tlv_type == 0xFE:
                print "Error Detction Code Found."
            else:
                print "[TLV] %s : %s : %s" % (hex(tlv_type),
                                        len(tlv_value),
                                        APDU.get_hex(tlv_value))


        self._splash("Security Object (%s)" % (APDU.get_hex(object_id)))


    def _print_fingerprint(self, tv_data, registered_id, object_id):
        """
            Print Fingerprint data from PIV
            
            REQUIRES PIN!
            
            Ref: SP800-73-1
        """

        self._splash("Fingerprint")
        # Loop over extracted data and print nicely formatted
        for tv in tv_data:
            tlv_type = tv[0]
            tlv_value = tv[1]

            if tlv_type == 0xBC:
                print "Fingerprint: [length %d]" % len(tlv_value)
            elif tlv_type == 0xFE:
                print "Error Detection Code Found."
            else:
                print "[TLV] %s : %s : %s" % (hex(tlv_type),
                                        len(tlv_value),
                                        APDU.get_hex(tlv_value))
        self._splash("Fingerprint")


    def _print_facial_info(self, tv_data, registered_id, object_id):
        """
            Print Facial Information from PIV
            
            REQUIRES PIN!
            
            Ref: SP800-73-1
        """

        self._splash("Facial Information")
        for tv in tv_data:
            tlv_type = tv[0]
            tlv_value = tv[1]

            if tlv_type == 0xBC:
                print "Facial Image: [length %d]" % len(tlv_value)
            elif tlv_type == 0xFE:
                print "Error Detection Code Found."
            else:
                print "[TLV] %s : %s : %s" % (hex(tlv_type),
                                        len(tlv_value),
                                        APDU.get_hex(tlv_value))

        self._splash("Facial Information")


    def _print_person_info(self, tv_data, registered_id, object_id):
        """
            Print Person Information
            
            REQUIRES PIN!
            
            Ref: NISTIR-6887
        """

        self._splash("Person Instance Container")
        for tv in tv_data:
            tlv_type = tv[0]
            tlv_value = tv[1]

            if tlv_type == 0x01:
                print "First Name: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x02:
                print "Middle Name: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x03:
                print "Last Name: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x04:
                print "Candency Name: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x05:
                print "Personal Identifier: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x06:
                print "DOB: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x07:
                print "Sex: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x08:
                print "PI Type Code: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x11:
                print "Blood Type: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x17:
                print "DoD EDI PI: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x18:
                print "Organ Donor: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x62:
                print "Card Issue Date: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x63:
                print "Card Expiration Date: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x65:
                print "Date Demographic Data Loaded: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x66:
                print "Date Demographic Data Expires: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x67:
                print "Card Instance ID: %s" % APDU.get_str(tlv_value)
            else:
                print "[TLV] %s : %s : %s" % (hex(tlv_type),
                                        len(tlv_value),
                                        APDU.get_hex(tlv_value))

        self._splash("Person Instance Container")


    def _print_personnel(self, tv_data, registered_id, object_id):
        """
            Print Person Information
            
            REQUIRES PIN!
            
            Ref: NISTIR-6887
        """

        self._splash("Personnel Information")
        for tv in tv_data:
            tlv_type = tv[0]
            tlv_value = tv[1]

            if tlv_type == 0x19:
                print "Contractor Function Code: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x20:
                print "Gov Agency/Subagency Code: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x24:
                print "Branch: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x25:
                print "Pay Grade: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x26:
                print "Rank Code: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x34:
                print "Personnel Category Code: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x35:
                print "Non-US Gov Agency/Subagency Code: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0x36:
                print "Pay Plan Code: %s" % APDU.get_str(tlv_value)
            elif tlv_type == 0xD3:
                print "Personnel Entitlement Condition Code: %s" % APDU.get_str(tlv_value)
            else:
                print "[TLV] %s : %s : %s" % (hex(tlv_type),
                                        len(tlv_value),
                                        APDU.get_hex(tlv_value))
        self._splash("Personnel Information")


    def split_address(self, address):
        """ Split a 2 byte address into 2 individual bytes """
        P1 = (0b1111111100000000 & address) >> 8
        P2 = 0b11111111 & address
        return [P1, P2]


    def read_tl_v_buffer(self, address):
        """
            Read Type-Length buffer and Value buffer, concatenating all of the results 
            and returning a contiguous binary string
            
            @param address: Address of buffer.  Likely [0x00, 0x00]
            @return: Binary string of buffers merged into one 
        """

        addr = self.split_address(address)
        data, sw1, sw2 = self.apdu_read_buffer(addr[0], addr[1], 0x01, read_length=0x03)

        if sw1 != APDU.APDU_STATUS.SUCCESS:
            self._report_error(sw1, sw2, "Buffer read failed.")

            return

        # Figure out our length and where the data starts
        # @todo: Confirm that 0x81 and 0x82 apply here.
        if data[0] == 0x81:
            buffer_length = data[1]
            next_address = address + 3

        elif data[0] == 0x82:
            buffer_length = data[1] << 8 | data[2]
            next_address = address + 4

        else:
            buffer_length = data[0]
            next_address = address + 2

        # Read Type-Length values (0x01)
        addr = self.split_address(next_address)
        tl_buffer, sw1, sw2 = self.apdu_read_buffer(addr[0], addr[1], 0x01, read_length=buffer_length)
        tl_offset = 2

        rtn_list = []
        for i in range(buffer_length / 2):
            addr = self.split_address(next_address)
            tlv_type = tl_buffer[i * 2]
            tlv_length = tl_buffer[i * 2 + 1]

            data = []
            # Read data (0x02)
            if tlv_length > 0:

                data, sw1, sw2 = self.apdu_read_buffer(0, tl_offset, 0x02, read_length=tlv_length)
                tl_offset += tlv_length

            rtn_list.append([tlv_type, data])

        return rtn_list


    def apdu_read_buffer(self, p1, p2, buffer_type, read_length=64):
        """
            Send READ BUFFER APDU
            
            @param p1: MSB  of argument
            @param p2: LSB of argument
            @param buffer_type: 0x01 - Read Type-Length buffer, 
                                0x02 - Read Value buffer
            @param read_length: How many bytes to read
        
        """

        apdu_read = APDU.READ_BUFFER(p1, p2, buffer_type, read_length=read_length)

        data, sw1, sw2 = self._send_apdu(apdu_read)

        if sw1 != APDU.APDU_STATUS.SUCCESS:
            print "ERROR (%s,%s): READ BUFFER failed." % (hex(sw1), hex(sw2))

        return (data, sw1, sw2)


    def apdu_get_data_piv(self, address):
        """
            GET DATA APDU 
            
            Ref: SP800-73-1 / Table 6
            Card Capability Container                   5FC107  M
            Card Holder Unique Identifier               5FC102  M
            X.509 Certificate for PIV Authentication    5FC105  M
            Card Holder Fingerprint I                   5FC103  M
            Card Holder Fingerprint II                  5FC104  M
            Printed Information                         5FC109  O
            Card Holder Facial Image                    5FC108  O
            X.509 Certificate for Digital Signature     5FC10A  O
            X.509 Certificate for Key Management        5FC10B  O
            X.509 Certificate for Card Authentication   5FC101  O
            Security Object                             5FC106  M

            @param address: 3 byte address list
            @return (data,sw1,sw2)
        """

        apdu_get_data = APDU.GET_DATA_PIV(address)
        # Get returned data
        data, sw1, sw2 = self._send_apdu(apdu_get_data)
        if sw1 != APDU.APDU_STATUS.SUCCESS:
            print "ERROR (%s,%s): GET DATA failed." % (hex(sw1), hex(sw2))

        return data, sw1, sw2


    def apdu_sign_decrypt(self, input_data):
        """
            Send data to the CAC to be signed or decrypted.
            
            Ref: SP800-73-1 / Page 14
            
            @param data: Data to be signed or decrypted
            @return: (data, sw1, sw2) - Returns data decrypted or signed if successful
        """

        PADDING = 0xFF
        MAX_LEN = 128 # must be a divisor of 256

        # Pad the data
        while len(input_data) % 256 != 0:
            input_data.append(PADDING)

        chunk_count = len(input_data) / MAX_LEN

        for i in range(chunk_count):
            # Set P1 to indicate more data is coming
            P1 = 0b10000000
            if i == chunk_count - 1:
                P1 = 0x0
            # Exract the chunk of the data we are sending
            data_chunk = input_data[MAX_LEN * i:MAX_LEN * i + MAX_LEN]

            # Send the APDU
            apdu_cmd = APDU.SIGN_DECRYPT(data_chunk, P1=P1)
            # Get returned data
            data, sw1, sw2 = self._send_apdu(apdu_cmd)
            if sw1 != APDU.APDU_STATUS.SUCCESS:
                print "ERROR (%s,%s): SIGN/DECRYPT failed." % (hex(sw1), hex(sw2))
                break

        return (data, sw1, sw2)


    def select_nist_piv(self):
        """ SELECT NIST PIV """
        data, sw1, sw2 = self.apdu_select_application(APDU.APPLET.NIST_PIV)
        if sw1 != APDU.APDU_STATUS.SUCCESS:
            print "ERROR (%s,%s): SELECT PIV RID (%s) failed." % (hex(sw1),
                                                                  hex(sw2),
                                                                  APDU.get_hex(APDU.APPLET.NIST_PIV))
            return


    def read_object(self, registered_id, object_id, pix=[], pin=None):
        """
            Read a an Object from a given Applet (resource id) and return the 
            BER-TLV decoded data.
            
            1. SELECTs the Applet/PIX
            2. GET DATA from the Object
            3. decode the BER-TLV format
            
            @param registered_id: Applet's Registered ID (5 bytes)
            @param pix: Proprietary Identifier Extension (2-11 bytes)
            @param object_id: Object ID within the Resource
        """

        # Select object from the Applet
        if registered_id == APDU.APPLET.NIST_PIV:
            # Select the Transitional PIV, then select the appropriate Object
            self.apdu_select_application(registered_id)
            if pin is not None:
                data, sw1, sw2 = self.apdu_verify_pin(pin, 0x80)
            data, sw1, sw2 = self.apdu_get_data_piv(object_id)
        elif registered_id == APDU.APPLET.DOD_PIV or registered_id == APDU.APPLET.DOD_CAC:
            # Select Applet and Object using SELECT applciation apdu
            self.apdu_select_application(registered_id + pix)
            if pin is not None:
                data, sw1, sw2 = self.apdu_verify_pin(pin, 0x00)
            data, sw1, sw2 = self.apdu_select_object(object_id)
        else:
            self._report_error(sw1, sw2, "Could not read Object (%s) from Applet (%s)." % (APDU.get_hex(registered_id),
                                                                          APDU.get_hex(object_id))
                          )
            return None

        # @todo: Handle error cases 
        if sw1 != APDU.APDU_STATUS.SUCCESS:
            self._report_error(sw1, sw2, "Read Object failed. (RID:%s, OID:%s)" % (APDU.get_hex(registered_id),
                                APDU.get_hex(object_id)))
            return

        # Extract our data
        if registered_id == APDU.APPLET.NIST_PIV:
            tv_data = self._decode_ber_tlv(data)
        elif registered_id == APDU.APPLET.DOD_PIV or registered_id == APDU.APPLET.DOD_CAC:
            tv_data = self.read_tl_v_buffer(0x000)

        return tv_data

    def extract_cert(self, registered_id, object_id, cert_filename):
        """
            Will extract the certificate from the card and save it to a file on 
            disk.
            
            @param registered_id: RID of the applet to extract the cert from.
            @param object_id: Object ID of the cert to be extracted
            @param cert_filename: Filename to save the cert as on disk
        """

        # Read the data from the object
        data = self.read_object(registered_id, object_id)

        if data == None:
            logger.error("Failed to extract %s." % self._lookup_cert(registered_id, object_id))
            return

        # We know that all certs have the same format and where the cert is
        # Ref: SP800-73-1 / Page 47
        cert_data = None
        for tv in data:
            # 0x70 for certificates
            # 0x3E for CHUID cert
            if tv[0] == 0x70 or tv[0] == 0x3E:
                cert_data = tv[1]
                break

        if cert_data is None:
            logger.error("Certificate %s not found in APDU response." % self._lookup_cert(registered_id, object_id))
            return

        # Create file and write to it
        cert_f = open(cert_filename, "wb+")

        cert_f.write(struct.pack("%dB" % len(cert_data), *cert_data))

        cert_f.close()

        print "Saved %s to %s" % (self._lookup_cert(registered_id, object_id),
                                cert_filename)


    def save_nist_cert(self, oid, cert_filename):
        """
            Function to extract NIST certificates from the DoD CaC and save
            it as a file to disk.  This will also extract the PEM version and
            the public key with the appropriate file extensions.
            
            This function calls shell functions.  It's not the nicest way to do 
            it but I see no reason to require more Python modules.
            
            @param oid: Object ID of the cert to be extracted
            @param cert_filename: Filename to save the cert to disk as.
        """

        # Extract the cert to disk (with gzip extension
        self.extract_cert(APDU.APPLET.NIST_PIV,
                          oid,
                          cert_filename + ".gz")

        # ungzip it (remember the gzip extension was appeneded)
        subprocess.Popen(["gunzip", "-f", cert_filename + ".gz"])

        # extract public cert and PEM version of the cert
        p = subprocess.Popen(["openssl", "x509",
                              "-inform", "DER",
                              "-pubkey",
                               "-in", cert_filename,
                               "-out", cert_filename + ".pem"],
                              stdout=subprocess.PIPE)
        out, err = p.communicate()

        # Write our output file
        f = open(cert_filename + ".pub", "w+")
        f.write(out)
        f.close()


    def print_object(self, registered_id, object_id, pix=[], pin=None):
        """    
            Will read the Object from the given Applet/PIX and then print
            the results in human readable form.
            
            @param registered_id: Applet's Registered ID (5 bytes)
            @param pix: Proprietary Identifier Extension (2-11 bytes)
            @param object_id: Object ID within the Resource
        """

        # Read the data from the object
        tv_data = self.read_object(registered_id, object_id, pix=pix, pin=pin)

        if tv_data == None:
            logger.error("Could not retrive Object (%s) from Applet (%s)." % (APDU.get_hex(object_id),
                                                                               APDU.get_hex(registered_id))
                          )
            return

        # See if we have a print function for this object
        # CHUID
        if object_id in [APDU.OBJ_DOD_PIV.CHUID, APDU.OBJ_NIST_PIV.CHUID]:
            self._print_chuid(tv_data, registered_id, object_id)
        # CCC
        elif object_id in [APDU.OBJ_DOD_PIV.CCC, APDU.OBJ_NIST_PIV.CCC]:
            self._print_ccc(tv_data, registered_id, object_id)

        # X.509 PIV Cred Auth
        elif object_id in [APDU.OBJ_NIST_PIV.KEY_CRD_ATH]:
            self._print_x509_cert(tv_data, registered_id, object_id)
        # X.509 Dig Sign
        elif object_id in [APDU.OBJ_NIST_PIV.KEY_DIG_SIG]:
            self._print_x509_cert(tv_data, registered_id, object_id)
        # X.509 Key Management
        elif object_id in [APDU.OBJ_NIST_PIV.KEY_MNG]:
            self._print_x509_cert(tv_data, registered_id, object_id)
        # X.509 PIV Auth
        elif object_id in [APDU.OBJ_NIST_PIV.KEY_PIV_ATH]:
            self._print_x509_cert(tv_data, registered_id, object_id)
        # CAC PKI
        elif object_id in [APDU.OBJ_DOD_CAC.KEY_PKI_ENC, APDU.OBJ_DOD_CAC.KEY_PKI_ID, APDU.OBJ_DOD_CAC.KEY_PKI_SIG]:
            self._print_x509_cert(tv_data, registered_id, object_id)
        # Security Object
        elif object_id in [APDU.OBJ_DOD_PIV.SEC_OBJ, APDU.OBJ_NIST_PIV.SEC_OBJ]:
            self._print_sec_obj(tv_data, registered_id, object_id)
        # Fingerprints
        elif object_id in [APDU.OBJ_DOD_PIV.FNGR_PRNT, APDU.OBJ_NIST_PIV.FNGR_P1, APDU.OBJ_NIST_PIV.FNGR_P2]:
            self._print_fingerprint(tv_data, registered_id, object_id)
        # Facial Image
        elif object_id in [APDU.OBJ_DOD_PIV.FACE, APDU.OBJ_NIST_PIV.FACE]:
            self._print_facial_info(tv_data, registered_id, object_id)
        # Person Info
        elif object_id in [APDU.OBJ_DOD_CAC.CAC_PERSON]:
            self._print_person_info(tv_data, registered_id, object_id)
        # Personnel Info
        elif object_id in [APDU.OBJ_DOD_CAC.CAC_PERSONEL]:
            self._print_personnel(tv_data, registered_id, object_id)
        else:
            logger.error("No function implemented to print Object (%s) from Applet (%s)." % (APDU.get_hex(object_id),
                                                                               APDU.get_hex(registered_id))
                          )
            print tv_data
            return






class CreditCard(SmartCard):
    """
        Implements some known features of Visa smartcards
    """
    INFO_REC = 1
    INFO_SFI = 12

    def _parse_applet_info(self, data):
        """
            Parse the data we get back from selecting the applet
        """
        # Is this a FCI template?
        if data[0] == 0x6f:
            tlv = self._decode_ber_tlv(data)
            logger.info("FCI Template")
            
            template = self._decode_ber_tlv(tlv[0][1])
            # Parse template info
            for t in template:
                if t[0] == 0x84:
                    df_name = "".join(["%02X"%x for x in t[1]])
                    logger.info("DF Name: %s"%df_name)
                    
                if t[0] == 0xa5:
                    logger.info(" FCI Proprietary Template")
                    prop_template = self._decode_ber_tlv(t[1])
                    
                    # Parse embedded info
                    for pt in prop_template:
                        if pt[0] == 0x50:
                            app_label = "".join([str(unichr(x)) for x in pt[1]])
                            logger.info("  Application Label: %s"%app_label)
                        if pt[0] == 0x87:
                            logger.info("  Application Priority Indicator: %s"%pt[1][0])


    def select_visa_applet(self):
        """
            Will send the appropriate APDU to select the Visa applet
        """
        data, sw1, sw2 = self.apdu_select_application(APDU.APPLET.VISA)
        if sw1 != APDU.APDU_STATUS.SUCCESS:
            print "ERROR: This does not appear to be a valid VISA card!"
        else:
            self._parse_applet_info(data)
        
    
    def select_mastercard_applet(self):
        """
            Will send the appropriate APDU to select the Visa applet
        """
        data, sw1, sw2 = self.apdu_select_application(APDU.APPLET.MASTERCARD)
        if sw1 != APDU.APDU_STATUS.SUCCESS:
            print "ERROR: This does not appear to be a valid MasterCard!"
        else:
            self._parse_applet_info(data)

                

    def read_card_info(self):
        """
            Read known paramaters from a Visa smartcard
        """
        
        # REad the record from teh card
        data, sw1, sw2 = self.apdu_read_record(self.INFO_REC, self.INFO_SFI, cla=0x00)
        
        # Was it a succes?
        if sw1 == APDU.APDU_STATUS.SUCCESS:
            
            # Setup our dict
            info = {}
            
            tlv = self._decode_ber_tlv(data)
            
            # Is this application data?
            if tlv[0][0] == 0x70:

                # Parse the data in the application
                cc_info = self._decode_ber_tlv(tlv[0][1])
                for field in cc_info:
                    # Is it a name field?
                    if field[0] == 0x5f:
                        cc_data = "".join([chr(x) for x in field[1]])
                        
                        cc_data = cc_data.split("/")
                        info['last_name'] = cc_data[0].strip()
                        info['first_name'] = cc_data[1].strip()
                    
                    # Account info field?
                    if field[0] == 0x57:
                        cc_data = "".join(["%02X"%x for x in field[1]])
                        
                        k = cc_data.find('D')
                        
                        info['account_number'] = cc_data[:k]
                        
                        
                        info['exp_year'] = cc_data[k+1:k+3]
                        info['exp_month'] = cc_data[k+3:k+5]
                        info['service_first'] = cc_data[k+5]
                        info['service_second'] = cc_data[k+6] 
                        info['service_third'] = cc_data[k+7]
                        
            return info
        
        else:
            logger.error("Couldn't read card data.")
            return None

        
    

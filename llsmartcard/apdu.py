
"""
Copyright 2015, MASSACHUSETTS INSTITUTE OF TECHNOLOGY
Subject to FAR 52.227-11 – Patent Rights – Ownership by the Contractor (May 2014).
SPDX-License-Identifier: BSD-3-Clause

Return codes
     ref: http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816-4_6_basic_interindustry_commands.aspx
     ref: http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816-4_7_transmission_interindustry_commands.aspx
     """

import logging

class AUTH_KEYS:
    # http://www.cryptoshop.com/products/smartcards/gemalto-idcore-10-gemalto-top-im-gx4.html?___store=english&___from_store=default
    GEMALTO = [
               [0x47, 0x45, 0x4D, 0x58, 0x50, 0x52, 0x45, 0x53, 0x53, 0x4F, 0x53, 0x41, 0x4D, 0x50, 0x4C, 0x45],
               [0x47, 0x45, 0x4D, 0x58, 0x50, 0x52, 0x45, 0x53, 0x53, 0x4F, 0x53, 0x41, 0x4D, 0x50, 0x4C, 0x45],
               [0x47, 0x45, 0x4D, 0x58, 0x50, 0x52, 0x45, 0x53, 0x53, 0x4F, 0x53, 0x41, 0x4D, 0x50, 0x4C, 0x45]
               ]
    GEMALTO_MODUS_VISA2 = [0xA0, 0x00, 0x00, 0x00, 0x18, 0x43, 0x4D, 0x00]

class AUTH_KEY_IDX:
    AUTH = 0
    MAC = 1
    ENC = 2

class SECURE_CHANNEL:
    class DIVERSIFY:
        VISA2 = 0x00
    class MODE:
        NONE = 0x00
        MAC = 0X01
        MAC_ENC = 03


class SET_STATUS_PARAM:
    class TYPE:
        SECURITY_DOMAIN = 0b10000000
        APPLICATION = 0b01000000

    class STATE_CARD:
        # Card State
        OP_READY = 0b00000001
        INITIALIZED = 0b00000111
        SECURED = 0b00001111
        LOCKED = 0b01111111
        TERMINATED = 0b11111111

    class STATE_SEC_DOM:
        # Security Domain
        INSTALLED = 0b000011
        SELECTABLE = 0b00000111
        PERSONALIZED = 0b00001111
        LOCKED = 0b10000011


    class STATE_APP:
        # Application
        INSTALLED = 0b00000011
        LOCKED = 0b10000000
        UNLOCKED = 0b00000000


class SEARCH_CRITERIA:
    AID = [0x4F, 0x00]
# APDU Definitions
class APDU_CMD:
    """
        Lookup class for ADPU command values
        
        Reference: http://www.informit.com/articles/article.aspx?p=29265&seqNum=6
        Reference: http://techmeonline.com/most-used-smart-card-commands-apdu/
    """
    # Administrative
    GET_RESPONSE = 0xC0
    MANAGE_CHANNEL = 0x70
    ENVELOPE = 0xC2
    GET_DATA = 0xCA
    PUT_DATA = 0xDA
    GET_STATUS = 0xF2
    SET_STATUS = 0xF0
    # Data
    SELECT = 0xA4
    READ_RECORD = 0xB2
    WRITE_RECORD = 0xD2
    APPEND_RECORD = 0xE2
    UPDATE_RECORD = 0xDC
    READ_BUFFER = 0x52
    GET_DATA_PIV = 0xCB
    READ_BINARY = 0xB0
    WRITE_BINARY = 0xD0
    UPDATE_BINARY = 0xD6
    ERASE_BINARY = 0x0E
    # Security
    INIT_UPDATE = 0x50
    VERIFY = 0x20
    RESET_RETRY = 0x2C
    CHANGE_REF_DATA = 0x24
    SIGN_DECRYPT = 0x42
    EXTERNAL_AUTH = 0x82
    INTERNAL_AUTH = 0x88
    GET_CHALLENGE = 0x84


    TEST_CLASSES = [0x00, 0xC0, 0xF0, 0x80, 0xBC, 0x01]

class STATUS_WORDS:
    """
        Loockup class for common Status Words
    """
    SUCCESS = (0x90, 0x00)
    # Secure Channel
    AUTH_FAIL = (0x63, 0x00)
    NOT_FOUND = (0x6a, 0x88)
    COND_NOT_SATISFIED = (0x69, 0x85)

# APDU Return Status Codes
class APDU_STATUS:
    """
        Lookup class for common APDU SW1
    """
    MORE_DATA = 0x61
    WRONG_LENGTH = 0x6C
    SUCCESS = 0x90

class PIX_CAC:
    """
        Lookup class for PIX addresses on the CAC
    """
    PKI_APLT = [0x01, 0x00]
    PKI_APLT2 = [0x01, 0x02]
    PKI_APLT3 = [0x01, 0x01]
    GC_APLT = [0x02, 0x00]
    GC_APLT2 = [0x02, 0x01]
    AXS_CTL_APLT = [0x01, 0x00]

    CCC = [0xDB, 0x00]

    PIV_TRNS_APLT = [0x30, 0x00]

    PIV_END_PNT = [0x00, 0x00, 0x10, 0x00, 0x01, 0x00]

# Known Applet Identification Numbers
class APPLET:
    # Credit Cards
    MASTERCARD = [0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10]
    VISA = [0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10]

    # CAC
    NIST_PIV = [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00] + [0x10, 0x00, 0x01, 0x00]
    DOD_PIV = [0xA0, 0x00, 0x00, 0x01, 0x16] #, 0xDB, 0x00]
    DOD_CAC = [0xA0, 0x00, 0x00, 0x00, 0x79] + [0x01, 0x00]

    # Other
    HELLO = [0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0x01]

    # Security Domains
    SECURITY_GEMALTO = [0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]

class OBJ_NIST_PIV:
    # Ref: Cac End-Point Implementation Guide v1.22 / Page 33
    # Keys
    KEY_PIV_ATH = [0x5f, 0xc1, 0x05]
    KEY_DIG_SIG = [0x5f, 0xc1, 0x0A]
    KEY_MNG = [0x5f, 0xc1, 0x0B]
    KEY_CRD_ATH = [0x5f, 0xc1, 0x01]
    # Other
    CHUID = [0x5F, 0xC1, 0x02]
    CCC = [0x5F, 0xC1, 0x07]
    SEC_OBJ = [0x5f, 0xc1, 0x06]
    # Biometrics
    FNGR_P1 = [0x5F, 0xC1, 0x03]
    FNGR_P2 = [0x5F, 0xC1, 0x04]
    FACE = [0x5F, 0xC1, 0x08]

class OBJ_DOD_PIV:
    # Ref: Cac End-Point Implementation Guide v1.22 / Page 33
    # Keys
#    KEY_PIV_ATH = [0xA0, 0x01]
#    KEY_DIG_SIG = [0x01, 0x00]
#    KEY_MNG = [0x01, 0x02]
#    KEY_CRD_ATH = [0x05, 0x00]
    # Other
    CHUID = [0x30, 0x00]
    CCC = [0xDB, 0x00]
    SEC_OBJ = [0x90, 0x00]
    FACE = [0x60, 0x30]
    FNGR_PRNT = [0x60, 0x10]

class OBJ_DOD_CAC:
    # Ref: Cac End-Point Implementation Guide v1.22 / Page 33
    # Keys
    KEY_PKI_SIG = [0x01, 0x01] # Mapped to PIV Key Mgmt Key & PIV Digital Sign Key
    KEY_PKI_ID = [0x01, 0x00]
    KEY_PKI_ENC = [0x01, 0x02] # Mapped to PIV Key Mgmt Key & PIV Digital Sign Key
    # Other
    CAC_PERSON = [0x02, 0x00]
    CAC_PERSONEL = [0x02, 0x01]
    ACCESS_CONTROL = [0x02, 0x01]


# APDU Construction functions

def SIGN_DECRYPT(data, CLA=0x80, P1=0x00, P2=0x00):
    """
        CLA INS P1 P2 Lc DATA Le
        P1 - 0b1000000 (more blocks to follow), or 0
        P2 - 0x00
        Lc - length of data
        Le - expected length of returned data
    """
    return [CLA, APDU_CMD.SIGN_DECRYPT, P1, P2] + [len(data)] + data + [0x00]



def SELECT(data, CLA=0x00, P1=0x04, P2=0x00):
    """
        CLA INS P1 P2 Le DATA...
        P1 and P2: http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816-4_6_basic_interindustry_commands.aspx#table58
    """
    return [CLA, APDU_CMD.SELECT, P1, P2] + [len(data)] + data + [0x00]


def GET_DATA(P1, P2, CLA=0x80, Lc=0x00):
    """
        CLA INS P1 P2 Le
        Set Le to 0x00 then update when we get the return code
        
        @param P1: Most significant byte of address
        @param P2: Least significant byte of address
        @param CLA: Class
        @param Lc: Length to read 
    """
    return [CLA, APDU_CMD.GET_DATA, P1, P2, Lc]


def READ_BINARY(P1,P2, CLA=0x00, Lc=0x00):
    """
        CLA INS P1 P2 Le
        
        @param P1: If bit8=1 in P1, then bit7-6 are set to 0. bit3-1 of P1 are a short EF (Elementary File)
        @param P2: The offset of the first byte to be read in date units from the beginning of the file
        @param CLA: Class
        @param Lc: Length to read 
    """
    return [CLA, APDU_CMD.READ_BINARY, P1, P2, Lc]

def GET_DATA_PIV(address):
    """
        CLA INS P1 P2 Lc DATA Le
        Set Le to 0x00 then update when we get the return code
        
        @param address: Address of PIV object to read 
    """
    P1 = 0x3F
    P2 = 0xFF
    tag_list = [0x5c, len(address)] + address
    Lc = len(tag_list)
    Le = 0x00
    return [0x00, APDU_CMD.GET_DATA_PIV, P1, P2, Lc] + tag_list + [Le]


def READ_RECORD(P1, P2, CLA=0x00, Le=0x00):
    """
        CLA INS P1 P2 Le
        Set Le to 0x00 then update when we get the return code
        
        @param CLA: Class
        @param P1: Record Number
        @param P2: Reference Control (http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816-4_6_basic_interindustry_commands.aspx#table36)
        @param Le: Bytes to read
    """
    return [CLA, APDU_CMD.READ_RECORD] + [P1, P2, Le]


def READ_BUFFER(P1, P2, buffer_type, read_length=64, Lc=0x02, CLA=0x80):
    """
        CLA INS P1 P2 Lc DATA_FIELD Le
        
        @param P1: MSB of offset
        @param P2 LSB of offset
        @param buffer_type: 0x01 (Type-Length buffer), 0x02 (Value buffer)
        @param read_length: Number of bytes to read
        @param CLA: Class
        @return: byte list with constructed APDU command 
    
    """
    return [CLA, APDU_CMD.READ_BUFFER] + [P1, P2] + [Lc] + [buffer_type, read_length]


def INIT_UPDATE(P1, P2, challenge, CLA=0x80, Le=0x00):
    """
        CLA INS P1 P2 Lc DATA_FIELD Le
    
        @param P1: Key version number (Default: 0)
        @param P1: Key identifier (Default: 0)
        @param challenge: List of 8 bytes to be send as the Nonce
        @return: byte list with constructed APDU command 
    """
    return [CLA, APDU_CMD.INIT_UPDATE] + [P1, P2] + [len(challenge)] + challenge + [Le]

def EXTERNAL_AUTHENTICATE(P1, cryptogram, mac, P2=0x00, CLA=0x84, Le=0x00):
    """
        CLA INS P1 P2 Lc DATA_FIELD Le
    
        @param P1: Security Level: 0x00 - None, 0x01, C-MAC, 0x03, C-DECRYPTION and C-MAC
        @param P2: Always 0x00
        @param cryptogram: Host cryptogram to send to card
        @param mac: C-MAC for this APDU
        @return: byte list with constructed APDU command 
    """
    Lc = len(cryptogram)
    return [CLA, APDU_CMD.EXTERNAL_AUTH] + [P1, P2] + [Lc] + cryptogram + mac + [Le]

def GET_STATUS(P1, P2, search_criteria, Lc=None, CLA=0x80, Le=0x00):
    """
        CLA INS P1 P2 Lc DATA_FIELD Le
    
        @param P1:  80 - Issuer Security Domain
                    40 - Application Security Domain
                    20 - Executable Load Files only
                    10 - Executable Load Files and their Executable Modules only
        @param P2:  0bx0 - get all/first occurrence(s)
                    0bx1 - get next
                    0b0x - Response Structure 1
                    0b1x - Response Structure 2
        @param search_criteria: 4f00 used to indicated AID
        Reference: GP 2.1.1/ page 114
    """
    if Lc is None:
        Lc = len(search_criteria)
    return [CLA, APDU_CMD.GET_STATUS, P1, P2, Lc] + search_criteria + [ Le]

def SET_STATUS(P1, P2, data, CLA=0x80):
    """
        CLA INS P1 P2 Lc DATA_FIELD Le
    
        @param P1:  Status Type
                    0x80 Security Domain
                    0x40 Application
        @param P2:  State Coapdu_ntrol
                    0x80 Locked
                    0x00 Unlocked
                    (See Table 9-5)
        @param data: AID if setting application status 
        @param CLA: 0x80 or 0x84
        
        Reference: GP 2.1.1/11.10 page 163
    """
    Le = 0
    return [CLA, APDU_CMD.SET_STATUS, P1, P2, len(data)] + data + [Le]


def VERIFY_PIN(P2, PIN, P1=0x00, CLA=0x00):
    """
        @param pin: list of bytes (length 4-8 bytes)
        @param p1: 0x00 is only valid
        @param p2: Key location
        @return (data, sw1, sw2)
    """
    return [CLA, APDU_CMD.VERIFY, P1, P2, len(PIN)] + PIN


def RESET_RETRY_COUNT(P1, P2, puk, new_pin, CLA=0x00):
    """
        @param puk: list of bytes (length 4-8 bytes)
        @param new_pin: list of bytes (length 4-8 bytes)
        @param p1: 0x00, 0x01, or 0x02
        @param p2: Key location
        @return (data, sw1, sw2)
        
        Reference: ISO 7816-4 8.5.9
        Refere SP800-73-3 Pat 2
    """
    data = []
    if puk != None:
        data += puk
    if new_pin is not None:
        data += new_pin

    return [CLA, APDU_CMD.RESET_RETRY, P1, P2, len(data)] + data

def CHANGE_REFERENCE_DATA(P1, P2, old_pin, new_pin, CLA=0x00):
    """
        @param puk: list of bytes (length 4-8 bytes)
        @param new_pin: list of bytes (length 4-8 bytes)
        @param p1: 0x00, or 0x01 for the first time
        @param p2: Reference Data ID
                    0x00 - Global PIN
                    0x80- Application PIN
                    0x81 - Application PUK
        @return (data, sw1, sw2)
        
        Reference: ISO 7816-4 8.5.6
    """
    data = []
    data += old_pin
    data += new_pin

    return [CLA, APDU_CMD.CHANGE_REF_DATA, P1, P2, len(data)] + data

def GET_RESPONSE(Le):
    """
        CLA INS P1 P2 Le
    """
    return [0x00, APDU_CMD.GET_RESPONSE, 0x00, 0x00, Le]


# Supplemntary Functions

def get_hex(input_list):
    """
        Convert a list of bytes into hex string
    """
    if input_list is None:
        return ""
    o = ""
    for i in input_list:
        o += (hex(i)) + " "
    return o[:-1]


def get_str(input_list):
    """
        Convert list of bytes into a string
    """
    o = ""
    for i in input_list:
        o += (chr(i))
    return o




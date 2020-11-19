             _      _          _____                      _    _____              _  
            | |    | |        / ____|                    | |  / ____|            | | 
            | |    | |  _____| (___  _ __ ___   __ _ _ __| |_| |     __ _ _ __ __| | 
            | |    | | |______\___ \| '_ ` _ \ / _` | '__| __| |    / _` | '__/ _` | 
            | |____| |____    ____) | | | | | | (_| | |  | |_| |___| (_| | | | (_| | 
            |______|______|  |_____/|_| |_| |_|\__,_|_|   \__|\_____\__,_|_|  \__,_|

                    Authors: Chad Spensky (chad.spensky@ll.mit.edu)
                               Hongyi Hu (hongyi.hu@ll.mit.edu)


# Contents

 * examples/
	Some example scripts on how to use the library to interact with various 
	smartcards

 * docs/ 
	Contains some useful documents when working with smart cards that
	define some of the APDUs and RIDs.

# Install 

 * Install [pyDes](https://pypi.python.org/pypi/pyDes/) python library

 * Install [pyscard](http://pyscard.sourceforge.net/) python library

 * Install PC/SC
   >$ sudo apt-get install pcsc-tools pcscd

 * To install all of these just run:
   >$ ./install_dependencies.sh 


# Usage

 * For developing your own smart card application using llsmartcard, see 
	template.py

 * See `examples/` 


# Certificates 
 
  This section discusses how to work with the certificates on the CAC.

 * Extract Certificates
    python cac_crypto.py -x test

 * Working with certs (Referenced from [here](http://www.devco.net/archives/2006/02/13/public_-_private_key_encryption_using_openssl.php)).

  - Encrypt
  >$ openssl pkeyutl -encrypt -in <input plain text> -pubin -inkey [input public key] -out [output file]

  - Extract Public Key
  >$ openssl x509 -inform DER  -pubkey -in [input certificate]  > output.key


 * Example using certs:

   >$ echo "Hello World!" > input.txt
   
   >$ python cac_crypto.py -E -k test/cac/cac_pki_enc.pub -i input.txt -o input_encrypted.ssl 
   
   >$ python cac_crypto.py -D -i input_encrypted.ssl -c KEY_PKI_ENC -o input_decrypted.txt -p 77777777

# Notes

 * Certificates are returned in gzipped form.
  >	$ gunzip [cert.gz]

 * Certificates are in DER form
  >	$ openssl x509 -inform DER -in [cert]
  >	$ openssl x509 -issuer -email -startdate -enddate -inform DER -in [cert]
  >	$ openssl x509 -inform DER -noout -text -in [cert]

# Citation
Please use this DOI number reference, published on [Zenodo](https://zenodo.org), when citing the software:    
[![DOI](https://zenodo.org/badge/35278621.svg)](https://zenodo.org/badge/latestdoi/35278621)

# Disclaimer
<p align="center">
This work is sponsored by the Defense Information Systems Agency under Air Force Contract #FA8721-05-C-0002.  Opinions, interpretations, conclusions and recommendations are those of the author and are not necessarily endorsed by the United States Government.
<br>
© 2015 Massachusetts Institute of Technology 
</p>

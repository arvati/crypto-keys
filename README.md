# Crypto-keys
Javascript Tool to encrypt and decrypt PEM / DER keys

## Usage
Supported key types are PEM/DER.   
 * Public keys are encoded to the form of SubjectPublicKeyInfo (SPKI) defined as a part of X.509 public key certificate ([RFC5280](https://tools.ietf.org/html/rfc5280)). The detailed encoding rule for elliptic curve cryptographic keys is given in RFC5480. 
 * Private keys are encoded to hte form of PrivateKeyInfo defined in PKCS#8 ([RFC5958](https://tools.ietf.org/html/rfc5958)). The detailed encoding rule for elliptic curve cryptographic keys is given in [RFC5915](https://tools.ietf.org/html/rfc5915)  as well as SPKI. 

Please refer to [RFC3447](https://tools.ietf.org/html/rfc3447)  for the detailed encoding rule of RSA public and private keys.


## License
Licensed under the MIT license, see `LICENSE` file.

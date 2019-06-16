[![codecov](https://codecov.io/gh/arvati/crypto-keys/branch/master/graph/badge.svg)](https://codecov.io/gh/arvati/crypto-keys)

# Crypto-keys
 > Node Module for Cryptographic Key Utilities in JavaScript'

Node Javascript Tool to generate, encrypt and decrypt RSA and EC keys formated as PEM / DER.

Fork of [js-crypto-key-utils](https://www.npmjs.com/package/js-crypto-key-utils) to work only with node.js,  with less dependencies and not available for Octet-Formatted Key.    

Included code to generate private and public key pair with RSA or EC algorithm


## Usage
Supported key types are PEM/DER.   
 * Public keys are encoded to the form of SubjectPublicKeyInfo (SPKI) defined as a part of X.509 public key certificate ([RFC5280](https://tools.ietf.org/html/rfc5280)). The detailed encoding rule for elliptic curve cryptographic keys is given in RFC5480. 
 * Private keys are encoded to hte form of PrivateKeyInfo defined in PKCS#8 ([RFC5958](https://tools.ietf.org/html/rfc5958)). The detailed encoding rule for elliptic curve cryptographic keys is given in [RFC5915](https://tools.ietf.org/html/rfc5915)  as well as SPKI. 

Please refer to [RFC3447](https://tools.ietf.org/html/rfc3447)  for the detailed encoding rule of RSA public and private keys.

See examples of [Tests](https://github.com/arvati/crypto-keys/blob/master/docs/tests.md) and our [API](https://github.com/arvati/crypto-keys/blob/master/docs/docs.md).

## License
Licensed under the MIT license, see [LICENSE](https://github.com/arvati/crypto-keys/blob/master/LICENSE.md).

## Author
[Ademar Arvati Filho](https://github.com/arvati)    
[Contributors](https://github.com/arvati/crypto-keys/blob/master/AUTHORS.md).

# Credits
This fork is totally based on work published by [junkurihara](https://github.com/junkurihara) at [js-crypto-key-utils](https://github.com/junkurihara/jscu/tree/master/packages/js-crypto-key-utils)

It uses library publish by [Tom Wu](mailto:tjw@cs.Stanford.EDU) at [stanford jsbn](http://www-cs-students.stanford.edu/~tjw/jsbn/) to generate keypair in pure js.

Using Great Jekyll theme [Just the Docs](https://github.com/pmarsceill/just-the-docs) by [Patrick Marsceill](http://patrickmarsceill.com/)

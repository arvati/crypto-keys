const assert = require('chai').assert;
const crypto = require('crypto');
const cryptoKeys = require('../lib')

describe('Test creation of Private and Public Keys', () => {
    var self_ = this;
    var types = new Map ([
        ['ec',{
                modulusLength: 4096, 
                namedCurve: 'secp256k1', 
                publicKeyEncoding: {
                    type: 'spki', 
                    format: 'pem'
                }, 
                privateKeyEncoding: {
                    type: 'pkcs8', 
                    format: 'pem'
                    // cipher: 'aes-256-cbc',
                    // passphrase: 'top secret'
                }
            }
        ],
        ['rsa',{
                modulusLength: 1024,
                publicExponent:65537,
                publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
                },
                privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
                // cipher: 'aes-256-cbc',
                // passphrase: 'top secret'
                }
            }
        ]
    ]);
    before('Declare function to create KeyPair with node.js crypto', () => {
        // This will only work with higher versions of nodejs >=10
        self_.getKeyPair = (
            type = "ec", 
            options = {modulusLength: 4096, namedCurve: 'secp256k1', publicKeyEncoding: {type: 'spki', format: 'pem'}, privateKeyEncoding: {type: 'pkcs8', format: 'pem'}}
            ) => {
            return {publicKey, privateKey} = crypto.generateKeyPairSync(type, options)
        }
    })

    types.forEach((value, name) => {
            describe('Creation of ' + name + ' Keys', () => {
                it(name + ' Key Pair generation using node crypto', () => {
                    const {publicKey, privateKey} = self_.getKeyPair(name, value)
                    self_.publicKey = publicKey
                    self_.privateKey = privateKey
                    assert.isString(publicKey,'public key is not a string');
                    assert.isString(privateKey,'private key is not a string');
                })

                it('Check key type created is ' + name, () => {
                    type = new cryptoKeys('pem', self_.privateKey).keyType
                    assert.deepEqual(type, name.toUpperCase(),'not correct key type to test')
                })

                it('Importing ' + name + ' Private Key', () => {
                    self_.cryptoPrivateKey = new cryptoKeys('pem', self_.privateKey);
                    assert.instanceOf(self_.cryptoPrivateKey, cryptoKeys, 'private key is not a cryptoKeys object');
                })

                it('Exporting ' + name + ' Private Key', () => {
                    PrivateKey = self_.cryptoPrivateKey.der
                    assert.instanceOf(PrivateKey, Uint8Array, 'private key is not a Uint8Array')
                })

                it('Importing ' + name + ' Public Key', () => {
                    self_.cryptoPublicKey = new cryptoKeys('pem', self_.publicKey);
                    assert.instanceOf(self_.cryptoPublicKey, cryptoKeys, 'public key is not a cryptoKeys object');
                })

                it('Exporting ' + name + ' Public Key', () => {
                    PublicKey = self_.cryptoPublicKey.der
                    assert.instanceOf(PublicKey, Uint8Array, 'public key is not a Uint8Array')
                })

                it('Generating ' + name + ' key public from private key', () => {
                    cryptoPublicKey = cryptoKeys.getPublicKey(self_.cryptoPrivateKey)
                    assert.deepEqual(cryptoPublicKey,self_.cryptoPublicKey,'public key generated from private key is equal original public key');
                    assert.instanceOf(cryptoPublicKey, cryptoKeys, 'public key is not a cryptoKeys object');
                    assert.isFalse(cryptoPublicKey.isPrivate, 'publicKey must not be private')
                    assert.equal((cryptoPublicKey.pem).replace(/\n$/, ""),self_.publicKey .replace(/\n$/, ""), "public pem key is equal original public pem")
                })
            });
        }
    )
},true);
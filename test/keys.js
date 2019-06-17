const assert = require('chai').assert;
const crypto = require('crypto');
const cryptoKeys = require('../lib')

describe('Compatible with node.js crypto Private and Public Keys', () => {
    var self_ = this;

    before('Declare function to create KeyPair with node.js crypto', () => {
        // This will only work with higher versions of nodejs >=10
        self_.getKeyPair = (
            type = "ec", 
            options = {modulusLength: 4096, namedCurve: 'secp256k1', publicKeyEncoding: {type: 'spki', format: 'pem'}, privateKeyEncoding: {type: 'pkcs8', format: 'pem'}}
            ) => {
            return {publicKey, privateKey} = crypto.generateKeyPairSync(type, options)
        }
    })

    // config for PEM format
    new Map ([
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
    ]).forEach((value, name) => {
        describe('Creation of ' + name + ' Keys in PEM Format', () => {
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
                assert.isTrue(self_.cryptoPrivateKey.isPrivate, 'not a private key')
            })

            it('Exporting ' + name + ' Private Key', () => {
                privateKey = self_.cryptoPrivateKey.der
                cryptoPrivateKey = new cryptoKeys('der', privateKey);
                assert.instanceOf(privateKey, Uint8Array, 'private key is not a Uint8Array')
                assert.instanceOf(cryptoPrivateKey, cryptoKeys, 'private key is not a cryptoKeys object');
                assert.equal((self_.cryptoPrivateKey.pem).replace(/\n$/, ""),self_.privateKey .replace(/\n$/, ""), "private pem key is not equal original private pem")
            })

            it('Importing ' + name + ' Public Key', () => {
                self_.cryptoPublicKey = new cryptoKeys('pem', self_.publicKey);
                assert.instanceOf(self_.cryptoPublicKey, cryptoKeys, 'public key is not a cryptoKeys object');
                assert.isFalse(self_.cryptoPublicKey.isPrivate, 'not a public key')
            })

            it('Exporting ' + name + ' Public Key', () => {
                publicKey = self_.cryptoPublicKey.der
                cryptoPublicKey = new cryptoKeys('der', publicKey);
                assert.instanceOf(publicKey, Uint8Array, 'public key is not a Uint8Array')
                assert.instanceOf(cryptoPublicKey, cryptoKeys, 'public key is not a cryptoKeys object');
                assert.equal((self_.cryptoPublicKey.pem).replace(/\n$/, ""),self_.publicKey .replace(/\n$/, ""), "public pem key is not equal original public pem")
            })
            it('Generating ' + name + ' key public from private key', () => {
                cryptoPublicKey = cryptoKeys.getPublicKey(self_.cryptoPrivateKey)
                assert.deepEqual(cryptoPublicKey,self_.cryptoPublicKey,'public key generated from private key is not equal original public key');
                assert.instanceOf(cryptoPublicKey, cryptoKeys, 'public key is not a cryptoKeys object');
                assert.isFalse(cryptoPublicKey.isPrivate, 'publicKey must not be private')
                assert.equal((cryptoPublicKey.pem).replace(/\n$/, ""),self_.publicKey .replace(/\n$/, ""), "public pem key is not equal original public pem")
            })
        });
    })

    // config for DER format
    new Map ([
        ['ec',{
                modulusLength: 4096, 
                namedCurve: 'secp256k1', 
                publicKeyEncoding: {
                    type: 'spki', 
                    format: 'der'
                }, 
                privateKeyEncoding: {
                    type: 'pkcs8', 
                    format: 'der'
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
                format: 'der'
                },
                privateKeyEncoding: {
                type: 'pkcs8',
                format: 'der'
                // cipher: 'aes-256-cbc',
                // passphrase: 'top secret'
                }
            }
        ]
    ]).forEach((value, name) => {
        describe('Creation of ' + name + ' Keys in DER Format', () => {
            it(name + ' Key Pair generation using node crypto', () => {
                const {publicKey, privateKey} = self_.getKeyPair(name, value)
                self_.publicKey = publicKey
                self_.privateKey = privateKey
                assert.instanceOf(privateKey, Uint8Array, 'private key is not a Uint8Array')
                assert.instanceOf(publicKey, Uint8Array, 'public key is not a Uint8Array')
            })
            it('Check key type created is ' + name, () => {
                type = new cryptoKeys('der', self_.privateKey).keyType
                assert.deepEqual(type, name.toUpperCase(),'not correct key type to test')
            })
            it('Importing ' + name + ' Private Key', () => {
                self_.cryptoPrivateKey = new cryptoKeys('der', self_.privateKey);
                assert.instanceOf(self_.cryptoPrivateKey, cryptoKeys, 'private key is not a cryptoKeys object');
                assert.isTrue(self_.cryptoPrivateKey.isPrivate, 'not a private key')
            })
            it('Exporting ' + name + ' Private Key', () => {
                assert.deepEqual(self_.cryptoPrivateKey.der,new Uint8Array(self_.privateKey),'Exported privateKey Der must be equal original Der')
                assert.deepEqual(Buffer.from(self_.cryptoPrivateKey.der),self_.privateKey,'Exported privateKey Der must be equal original Der')
            })

            it('Importing ' + name + ' Public Key', () => {
                self_.cryptoPublicKey = new cryptoKeys('der', self_.publicKey);
                assert.instanceOf(self_.cryptoPublicKey, cryptoKeys, 'public key is not a cryptoKeys object');
                assert.isFalse(self_.cryptoPublicKey.isPrivate, 'not a public key')
            })

            it('Exporting ' + name + ' Public Key', () => {
                assert.deepEqual(self_.cryptoPublicKey.der,new Uint8Array(self_.publicKey),'Exported publicKey Der must be equal original Der')
                assert.deepEqual(Buffer.from(self_.cryptoPublicKey.der),self_.publicKey,'Exported publicKey Der must be equal original Der')
            })
            it('Generating ' + name + ' key public from private key', () => {
                cryptoPublicKey = cryptoKeys.getPublicKey(self_.cryptoPrivateKey)
                assert.deepEqual(cryptoPublicKey,self_.cryptoPublicKey,'public key generated from private key is not equal original public key');
                assert.instanceOf(cryptoPublicKey, cryptoKeys, 'public key is not a cryptoKeys object');
                assert.isFalse(cryptoPublicKey.isPrivate, 'publicKey must not be private')
                assert.deepEqual(Buffer.from(cryptoPublicKey.der),self_.publicKey, "public der key is not equal original public der")
                assert.deepEqual(cryptoPublicKey.der,new Uint8Array(self_.publicKey), "public der key is not equal original public der")
            })
        });
    })

    // config for PEM format encrypted
    const password = 'top secret'
    new Map ([
        ['ec',{
                modulusLength: 4096, 
                namedCurve: 'secp256k1', 
                publicKeyEncoding: {
                    type: 'spki', 
                    format: 'pem'
                }, 
                privateKeyEncoding: {
                    type: 'pkcs8', 
                    format: 'pem',
                    cipher: 'aes-256-cbc',
                    passphrase: password
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
                format: 'pem',
                cipher: 'aes-256-cbc',
                passphrase: password
                }
            }
        ]
    ]).forEach((value, name) => {
        describe('Creation of ' + name + ' Keys in PEM Format Encrypted', () => {
            it(name + ' Key Pair generation using node crypto', () => {
                const {publicKey, privateKey} = self_.getKeyPair(name, value)
                self_.publicKey = publicKey
                self_.privateKey = privateKey
                assert.isString(publicKey,'public key is not a string');
                assert.isString(privateKey,'private key is not a string');
            })

            it('Check key type created is ' + name, () => {
                type = new cryptoKeys('pem', self_.privateKey).getKeyType(password)
                assert.deepEqual(type, name.toUpperCase(),'not correct key type to test')
            })

            it('Importing ' + name + ' Private Key', () => {
                self_.cryptoPrivateKey = new cryptoKeys('pem', self_.privateKey);
                assert.instanceOf(self_.cryptoPrivateKey, cryptoKeys, 'private key is not a cryptoKeys object');
                assert.isTrue(self_.cryptoPrivateKey.isPrivate, 'not a private key')
            })

            it('Exporting ' + name + ' Private Key', () => {
                privateKey = self_.cryptoPrivateKey.der
                cryptoPrivateKey = new cryptoKeys('der', privateKey);
                assert.instanceOf(privateKey, Uint8Array, 'private key is not a Uint8Array')
                assert.instanceOf(cryptoPrivateKey, cryptoKeys, 'private key is not a cryptoKeys object');
                assert.equal((self_.cryptoPrivateKey.pem).replace(/\n$/, ""),self_.privateKey .replace(/\n$/, ""), "private pem key is not equal original private pem")
            })

            it('Importing ' + name + ' Public Key', () => {
                self_.cryptoPublicKey = new cryptoKeys('pem', self_.publicKey);
                assert.instanceOf(self_.cryptoPublicKey, cryptoKeys, 'public key is not a cryptoKeys object');
                assert.isFalse(self_.cryptoPublicKey.isPrivate, 'not a public key')
            })

            it('Exporting ' + name + ' Public Key', () => {
                publicKey = self_.cryptoPublicKey.der
                cryptoPublicKey = new cryptoKeys('der', publicKey);
                assert.instanceOf(publicKey, Uint8Array, 'public key is not a Uint8Array')
                assert.instanceOf(cryptoPublicKey, cryptoKeys, 'public key is not a cryptoKeys object');
                assert.equal((self_.cryptoPublicKey.pem).replace(/\n$/, ""),self_.publicKey .replace(/\n$/, ""), "public pem key is not equal original public pem")
            })
            it('Generating ' + name + ' key public from private key', () => {
                cryptoPublicKey = cryptoKeys.getPublicKey(self_.cryptoPrivateKey,password)
                assert.deepEqual(cryptoPublicKey,self_.cryptoPublicKey,'public key generated from private key is not equal original public key');
                assert.instanceOf(cryptoPublicKey, cryptoKeys, 'public key is not a cryptoKeys object');
                assert.isFalse(cryptoPublicKey.isPrivate, 'publicKey must not be private')
                assert.equal((cryptoPublicKey.pem).replace(/\n$/, ""),self_.publicKey .replace(/\n$/, ""), "public pem key is not equal original public pem")
            })
        });
    })

    new Map ([
        ['ec and aes-256-cbc',{
            cipher: 'aes-256-cbc',
            type: 'ec'
            }
        ],
        ['rsa and aes-256-cbc',{
            cipher: 'aes-256-cbc',
            type: 'rsa'
            }
        ],
        ['ec and aes-192-cbc',{
            cipher: 'aes-192-cbc',
            type: 'ec'
            }
        ],
        ['rsa and aes-192-cbc',{
            cipher: 'aes-192-cbc',
            type: 'rsa'
            }
        ],
        ['ec and aes-128-cbc',{
            cipher: 'aes-128-cbc',
            type: 'ec'
            }
        ],
        ['rsa and aes-128-cbc',{
            cipher: 'aes-128-cbc',
            type: 'rsa'
            }
        ],
        ['ec and des-ede3-cbc',{
            cipher: 'des-ede3-cbc',
            type: 'ec'
            }
        ],
        ['rsa and des-ede3-cbc',{
            cipher: 'des-ede3-cbc',
            type: 'rsa'
            }
        ],
    ]).forEach((value, name) => {
        describe('Creation of ' + name + ' Keys in PEM Format Encrypted', () => {
            it(name + ' Key Pair generation using node crypto', () => {
                options = { 
                    publicKeyEncoding: {
                        type: 'spki', 
                        format: 'pem'
                    }, 
                    privateKeyEncoding: {
                        type: 'pkcs8', 
                        format: 'pem',
                        cipher: value.cipher,
                        passphrase: password
                    }
                }
                if (value.type === 'ec') options = Object.assign(options,{modulusLength: 4096, namedCurve: 'secp256k1' })
                else if (value.type === 'rsa') options = Object.assign(options,{modulusLength: 2048, publicExponent:65537 })
                else throw new Error('Invalid key type must be ec or rsa')
                const {publicKey, privateKey} = self_.getKeyPair(value.type, options)
                self_.publicKey = publicKey
                self_.privateKey = privateKey
                assert.isString(publicKey,'public key is not a string');
                assert.isString(privateKey,'private key is not a string');
            }).timeout(5000)
            it('Check key ' + name + ' created is type ' + value.type, () => {
                type = new cryptoKeys('pem', self_.privateKey).getKeyType(password)
                assert.deepEqual(type, value.type.toUpperCase(),'not correct key type to test')
            })
            it('Importing ' + name + ' Private Key', () => {
                self_.cryptoPrivateKey = new cryptoKeys('pem', self_.privateKey);
                assert.instanceOf(self_.cryptoPrivateKey, cryptoKeys, 'private key is not a cryptoKeys object');
                assert.isTrue(self_.cryptoPrivateKey.isPrivate, 'not a private key')
            })
            it('Importing ' + name + ' Public Key', () => {
                self_.cryptoPublicKey = new cryptoKeys('pem', self_.publicKey);
                assert.instanceOf(self_.cryptoPublicKey, cryptoKeys, 'public key is not a cryptoKeys object');
                assert.isFalse(self_.cryptoPublicKey.isPrivate, 'not a public key')
            })
            it('Generating ' + name + ' key public from private key', () => {
                cryptoPublicKey = cryptoKeys.getPublicKey(self_.cryptoPrivateKey,password)
                assert.deepEqual(cryptoPublicKey,self_.cryptoPublicKey,'public key generated from private key is not equal original public key');
                assert.instanceOf(cryptoPublicKey, cryptoKeys, 'public key is not a cryptoKeys object');
                assert.isFalse(cryptoPublicKey.isPrivate, 'publicKey must not be private')
                assert.equal((cryptoPublicKey.pem).replace(/\n$/, ""),self_.publicKey .replace(/\n$/, ""), "public pem key is not equal original public pem")
            })
        });
    })

    new Map ([
        ['ec and secp256k1','secp256k1'],
        ['ec and secp521r1','secp521r1'],
        ['ec and secp384r1','secp384r1'],
        ['ec and prime256v1','prime256v1']
    ]).forEach((value, name) => {
        describe('Creation of ' + name + ' Keys in PEM Format Encrypted', () => {
            it(name + ' Key Pair generation using node crypto', () => {
                options = { 
                    modulusLength: 2048, 
                    namedCurve: value,
                    publicKeyEncoding: {
                        type: 'spki', 
                        format: 'pem'
                    }, 
                    privateKeyEncoding: {
                        type: 'pkcs8', 
                        format: 'pem',
                        cipher: 'aes-256-cbc',
                        passphrase: password
                    }
                }
                const {publicKey, privateKey} = self_.getKeyPair('ec', options)
                self_.publicKey = publicKey
                self_.privateKey = privateKey
                assert.isString(publicKey,'public key is not a string');
                assert.isString(privateKey,'private key is not a string');
            }).timeout(5000)
            it('Check key ' + name + ' created is type ec', () => {
                type = new cryptoKeys('pem', self_.privateKey).getKeyType(password)
                assert.deepEqual(type, 'EC', 'not correct key type to test')
            }).timeout(10000)
            it('Importing ' + name + ' Private Key', () => {
                self_.cryptoPrivateKey = new cryptoKeys('pem', self_.privateKey);
                assert.instanceOf(self_.cryptoPrivateKey, cryptoKeys, 'private key is not a cryptoKeys object');
                assert.isTrue(self_.cryptoPrivateKey.isPrivate, 'not a private key')
            })
            it('Importing ' + name + ' Public Key', () => {
                self_.cryptoPublicKey = new cryptoKeys('pem', self_.publicKey);
                assert.instanceOf(self_.cryptoPublicKey, cryptoKeys, 'public key is not a cryptoKeys object');
                assert.isFalse(self_.cryptoPublicKey.isPrivate, 'not a public key')
            })
            it('Generating ' + name + ' key public from private key', () => {
                cryptoPublicKey = cryptoKeys.getPublicKey(self_.cryptoPrivateKey,password)
                assert.deepEqual(cryptoPublicKey,self_.cryptoPublicKey,'public key generated from private key is not equal original public key');
                assert.instanceOf(cryptoPublicKey, cryptoKeys, 'public key is not a cryptoKeys object');
                assert.isFalse(cryptoPublicKey.isPrivate, 'publicKey must not be private')
                assert.equal((cryptoPublicKey.pem).replace(/\n$/, ""),self_.publicKey .replace(/\n$/, ""), "public pem key is not equal original public pem")
            })
        });
    })

},true);
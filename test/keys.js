const assert = require('chai').assert;
const crypto = require('crypto');
const cryptoKeys = require('../lib')

describe('Test creation of Private and Public Keys', () => {

    var self_ = this;
    before('Declare function to create KeyPair with node.js crypto', () => {
        self_.getKeyPair = (
            type = "ec", 
            options = {modulusLength: 4096, namedCurve: 'secp256k1', publicKeyEncoding: {type: 'spki', format: 'pem'}, privateKeyEncoding: {type: 'pkcs8', format: 'pem'}}
            ) => {
            return {publicKey, privateKey} = crypto.generateKeyPairSync(type, options)
        }
    })

    describe('Creation of EC Keys', () => {

        it('EC Key Pair generation using node crypto', () => {
            // This will only work with higher versions of nodejs >=10
            const options = {
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
            const {publicKey, privateKey} = self_.getKeyPair('ec', options)
            self_.publicKey = publicKey
            self_.privateKey = privateKey
            assert.isString(publicKey,'public key is not a string');
            assert.isString(privateKey,'private key is not a string');
        })

        it('Importing EC Private Key', () => {
            self_.cryptoPrivateKey = new cryptoKeys('pem', self_.privateKey);
            assert.instanceOf(self_.cryptoPrivateKey, cryptoKeys, 'private key is not a cryptoKeys object');
        })

        it('Exporting EC Private Key', () => {
            PrivateKey = self_.cryptoPrivateKey.der
            assert.instanceOf(PrivateKey, Uint8Array, 'private key is not a Uint8Array')
        })

        it('Importing EC Public Key', () => {
            self_.cryptoPublicKey = new cryptoKeys('pem', self_.publicKey);
            assert.instanceOf(self_.cryptoPublicKey, cryptoKeys, 'public key is not a cryptoKeys object');
        })

        it('Exporting EC Public Key', () => {
            PublicKey = self_.cryptoPublicKey.der
            assert.instanceOf(PublicKey, Uint8Array, 'public key is not a Uint8Array')
        })

        it('Generating EC key public from private key', () => {
            cryptoPublicKey = cryptoKeys.getPublicKey(self_.cryptoPrivateKey)
            assert.deepEqual(cryptoPublicKey,self_.cryptoPublicKey,'public key generated from private key is equal original public key');
            assert.instanceOf(cryptoPublicKey, cryptoKeys, 'public key is not a cryptoKeys object');
            assert.isFalse(cryptoPublicKey.isPrivate, 'publicKey must not be private')
            assert.equal((cryptoPublicKey.pem).replace(/\n$/, ""),self_.publicKey .replace(/\n$/, ""), "public pem key is equal original public pem")
        })
    });


    describe('Creation of RSA Keys', () => {

        it('RSA Key Pair generation using node crypto', () => {
            // This will only work with higher versions of nodejs >=10
            const options = {
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
            const {publicKey, privateKey} = self_.getKeyPair('rsa', options)
            self_.publicKey = publicKey
            self_.privateKey = privateKey
            assert.isString(publicKey,'public key is not a string');
            assert.isString(privateKey,'private key is not a string');
        })

        it('Importing RSA Private Key', () => {
            self_.cryptoPrivateKey = new cryptoKeys('pem', self_.privateKey);
            assert.instanceOf(self_.cryptoPrivateKey, cryptoKeys, 'private key is not a cryptoKeys object');
        })

        it('Exporting RSA Private Key', () => {
            PrivateKey = self_.cryptoPrivateKey.der
            assert.instanceOf(PrivateKey, Uint8Array, 'private key is not a Uint8Array')
        })

        it('Importing RSA Public Key', () => {
            self_.cryptoPublicKey = new cryptoKeys('pem', self_.publicKey);
            assert.instanceOf(self_.cryptoPublicKey, cryptoKeys, 'public key is not a cryptoKeys object');
        })

        it('Exporting RSA Public Key', () => {
            PublicKey = self_.cryptoPublicKey.der
            assert.instanceOf(PublicKey, Uint8Array, 'public key is not a Uint8Array')
        })

        it('Generating RSA key pair ...', () => {
            cryptoPublicKey = cryptoKeys.getPublicKey(self_.cryptoPrivateKey)
            assert.deepEqual(cryptoPublicKey,self_.cryptoPublicKey,'public key generated from private key is equal original public key');
            assert.instanceOf(cryptoPublicKey, cryptoKeys, 'public key is not a cryptoKeys object');
            assert.isFalse(cryptoPublicKey.isPrivate, 'publicKey must not be private')
            assert.equal((cryptoPublicKey.pem).replace(/\n$/, ""),self_.publicKey .replace(/\n$/, ""), "public pem key is equal original public pem")
        })
    });
},true);
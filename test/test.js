const assert = require('chai').assert;
const crypto = require('crypto');
const keyutil = require('../lib')

// EXPORT OPTIONS
// options.outputPublic : boolean - get public key derived from private key
// options.compact : boolean - only for EC
// options.encryptParams - only when exporting to pem or der format
//         .passphrase - string
//         .algorithm - 'pbes2' as default, other 'pbeWithMD5AndDES-CBC', 'pbeWithSHA1AndDES-CBC'
//         .iterationCount - 2048 as default
//         more options if 'pbes2'
//         .cipher - 'aes256-cbc' as default, others 'des-ede3-cbc', 'aes128-cbc', 'aes192-cbc'
//         .prf - 'hmacWithSHA256' as default, others 'hmacWithSHA1', 'hmacWithSHA384', 'hmacWithSHA512'

// namedCurves compatible for EC keys:
//     'P-256': 'p256'
//     'P-384': 'p384'
//     'P-521': 'p521'
//     'P-256K': 'secp256k1' <= only this at node crypto

describe('Test 1', () => {
    describe('Teste 1.1', () => {
        it('My test', () => {
            assert.isTrue(true);
        })
    })
},true)

describe('Node Module for Cryptographic Key Utilities in JavaScript', () => {

    const getKeyPair = (type = "ec", options = {modulusLength: 4096, namedCurve: 'secp256k1', publicKeyEncoding: {type: 'spki', format: 'pem'}, privateKeyEncoding: {type: 'pkcs8', format: 'pem'}}) => {
        return {publicKey, privateKey} = crypto.generateKeyPairSync(type, options)
    }
    
      it('Default Key Pair generation using crypto', () => {
        // This will only work with higher versions of nodejs >=10
        const {publicKey, privateKey} = getKeyPair()
        assert.isString(publicKey,'public key is not a string');
        assert.isString(privateKey,'public key is not a string');
      })

      describe('PEM RSA key Pair', () => {
        it('Generating key pair ...', () => {
            this._privateKey = new keyutil('create', {type:'rsa', modulusLength:2048, publicExponent:65537});
            this._publicKey = new keyutil('jwk', this._privateKey.export('jwk', {outputPublic: true}) )
            this._privateKey.encrypt('top secret')
            assert.isObject(this._publicKey,'public key is not a object');
            assert.isObject(this._privateKey,'public key is not a object');
        }).timeout(10000);
        it('isPrivate of publicKey is False', () => {
            assert.isFalse(this._publicKey.isPrivate);
        });
        it('isEncrypted of publicKey is False', () => {
            assert.isFalse(this._publicKey.isEncrypted);
        });
        it('Key type of publicKey is RSA', () => {
            assert.equal(this._publicKey.keyType, 'RSA');
        });
        it('isPrivate of privateKey is True', () => {
            assert.isTrue(this._privateKey.isPrivate);
        });
        it('isEncrypted of privateKey is True', () => {
            assert.isTrue(this._privateKey.isEncrypted);
        });
        it('Decrypt privateKey with wrong password', () => {
            assert.throws(()=>this._privateKey.decrypt('just secret'),Error,'DecryptionFailure')
        });
        it('Decrypt privateKey with password', () => {
            assert.isTrue(this._privateKey.decrypt('top secret'));
        });
        it('Key type of privateKey is RSA', () => {
            assert.equal(this._privateKey.keyType, 'RSA');
        });
        it('Export privateKey as publicKey', () => {
            const options = {
                modulusLength: 1024,
                publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
                },
                privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem',
                cipher: 'aes-256-cbc',
                passphrase: 'top secret'
                }
            }
            const {publicKey, privateKey} = getKeyPair('rsa', options)
            key = new keyutil('pem', privateKey);
            key.decrypt('top secret')
            assert.equal((key.export('pem', {outputPublic: true})).replace(/\n$/, ""),publicKey.replace(/\n$/, ""))
        })
        it('Encrypt privateKey with password', () => {
            assert.isTrue(this._privateKey.encrypt('top secret'));
        });
        it('Sign String with encrypted private key and verify with public key', () => {
            //console.info(crypto.getHashes() )
            const value = 'My text to encrypt and verify'
            const privateKey = this._privateKey.pem;
            var signature = crypto.createSign("RSA-SHA256").
                update(value).
                sign({key: privateKey,
                    passphrase: 'top secret',
                    padding:crypto.constants.RSA_PKCS1_PSS_PADDING, 
                    saltLength:10}, "base64");
            const publicKey = this._publicKey.pem;
            var verified = crypto.createVerify("RSA-SHA256")
                .update(value)
                .verify({key: publicKey, 
                    padding:crypto.constants.RSA_PKCS1_PSS_PADDING, 
                    saltLength:10}, 
                    signature, "base64");
            assert.isTrue(verified);
        })
    })
    describe('PEM EC key Pair', () => {
        it('Generating key pair ...', () => {
            this._privateKey = new keyutil('create', {type:'ec', namedCurve:'P-256K'});
            this._publicKey = new keyutil('jwk', this._privateKey.export('jwk', {outputPublic: true}) )
            this._privateKey.encrypt('top secret')
            assert.isObject(this._publicKey,'public key is not a object');
            assert.isObject(this._privateKey,'public key is not a object');
        })
        it('isPrivate of publicKey is False', () => {
            assert.isFalse(this._publicKey.isPrivate);
        });
        it('isEncrypted of publicKey is False', () => {
            assert.isFalse(this._publicKey.isEncrypted);
        });
        it('Key type of publicKey is EC', () => {
            assert.equal(this._publicKey.keyType, 'EC');
        });
        it('isPrivate of privateKey is True', () => {
            assert.isTrue(this._privateKey.isPrivate);
        });
        it('isEncrypted of privateKey is True', () => {
            assert.isTrue(this._privateKey.isEncrypted);
        });
        it('Decrypt privateKey with wrong password', () => {
            assert.throws(()=>{this._privateKey.decrypt('just secret')},Error,'DecryptionFailure')
        });
        it('Decrypt privateKey with password', () => {
            assert.isTrue(this._privateKey.decrypt('top secret'));
        });
        it('Key type of privateKey is EC', () => {
            assert.equal(this._privateKey.keyType, 'EC');
        });
        it('Export privateKey as publicKey', () => {
            const options = {
                namedCurve: 'secp256k1',
                publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
                },
                privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem',
                cipher: 'aes-256-cbc',
                passphrase: 'top secret'
                }
            }
            const {publicKey, privateKey} = getKeyPair('ec', options)
            key = new keyutil('pem', privateKey);
            key.decrypt('top secret')
            assert.equal((key.export('pem', {outputPublic: true})).replace(/\n$/, ""),publicKey.replace(/\n$/, ""))
        })
        it('Encrypt privateKey with password', () => {
            assert.isTrue(this._privateKey.encrypt('new secret'));
        });
        it('Export privateKey with password', () => {
            privateKey = new keyutil('der', this._privateKey.der); 
            originalPrivateKey = new keyutil('pem', this._privateKey.pem); 
            assert.deepEqual(privateKey.der,originalPrivateKey.der);
            assert.throws(()=>{this._privateKey.jwk},Error,'DecryptionRequired')
        });
        it('Sign String with encrypted private key and verify with public key', async () => {
            //this._privateKey.encrypt('new secret')
            const value = 'My text to encrypt and verify'
            const privateKey = this._privateKey.pem;
            var signature = crypto.createSign("RSA-SHA256").
                update(value).
                sign({key: privateKey,
                    passphrase: 'new secret',
                    format:'pem',
                    padding:crypto.constants.RSA_PKCS1_PSS_PADDING, 
                    saltLength:10}, "base64");
            const publicKey = this._publicKey.pem;
            var verified = crypto.createVerify("RSA-SHA256")
                .update(value)
                .verify({key: publicKey, 
                    padding:crypto.constants.RSA_PKCS1_PSS_PADDING, 
                    saltLength:10}, 
                    signature, "base64");
            assert.isTrue(verified);
        })
    })
},true);
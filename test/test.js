const assert = require('chai').assert;
const crypto = require('crypto');
const keyutil = require('../lib/')
const getKeyPair = keyutil.getKeyPair

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



describe('Node Module for Cryptographic Key Utilities in JavaScript', () => {
  describe('Using Node Crypto to generate key Pair', () => {
      it('Default Key Pair generation', async () => {
        const  options = {modulusLength: 4096, namedCurve: 'secp256k1', publicKeyEncoding: {type: 'spki', format: 'pem'}, privateKeyEncoding: {type: 'pkcs8', format: 'pem'}}
        const {publicKey, privateKey} = crypto.generateKeyPairSync('ec', options)
        //console.info(publicKey)
        //console.info(privateKey)
        assert.isString(publicKey,'public key is not a string')
        assert.isString(privateKey,'public key is not a string');
      })
      describe('PEM RSA key Pair', () => {
        before('Generating key pair ...', () => {
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
            this._pemPublicKey = publicKey
            this._pemPrivateKey = privateKey
            this._publicKey = new keyutil('pem', publicKey);
            this._privateKey = new keyutil('pem', privateKey);
        })
        it('isPrivate of publicKey is False', async () => {
            assert.isFalse(await this._publicKey.isPrivate);
        });
        it('isEncrypted of publicKey is False', async () => {
            assert.isFalse(await this._publicKey.isEncrypted);
        });
        it('Key type of publicKey is RSA', async () => {
            assert.equal(await this._publicKey.keyType, 'RSA');
        });
        it('isPrivate of privateKey is True', async () => {
            assert.isTrue(await this._privateKey.isPrivate);
        });
        it('isEncrypted of privateKey is True', async () => {
            assert.isTrue(await this._privateKey.isEncrypted);
        });
        it('Decrypt privateKey with wrong password', async () => {
            try {
                await this._privateKey.decrypt('just secret')
                assert.isTrue(false)
              } catch (e) {
                assert.isTrue(e.message === 'FailedToDecryptNode: DecryptionFailure')
              }
              
        });
        it('Decrypt privateKey with password', async () => {
            assert.isTrue(await this._privateKey.decrypt('top secret'));
        });
        it('Key type of privateKey is RSA', async () => {
            assert.equal(await this._privateKey.keyType, 'RSA');
        });
        it('Export privateKey as publicKey', async () => {
            assert.equal((await this._privateKey.export('pem', {outputPublic: true})).replace(/\n$/, ""),this._pemPublicKey.replace(/\n$/, ""))
        })
        it('Encrypt privateKey with password', async () => {
            assert.isTrue(await this._privateKey.encrypt('top secret'));
        });
        it('Sign String with encrypted private key and verify with public key', async () => {
            //console.info(crypto.getHashes() )
            const value = 'My text to encrypt and verify'
            const privateKey = await this._privateKey.pem;
            var signature = crypto.createSign("RSA-SHA256").
                update(value).
                sign({key: privateKey,
                    passphrase: 'top secret',
                    padding:crypto.constants.RSA_PKCS1_PSS_PADDING, 
                    saltLength:10}, "base64");
            const publicKey = await this._publicKey.pem;
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
        before('Generating key pair ...', () => {
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
            this._pemPublicKey = publicKey
            this._pemPrivateKey = privateKey
            this._publicKey = new keyutil('pem', publicKey);
            this._privateKey = new keyutil('pem', privateKey);
        })
        it('isPrivate of publicKey is False', async () => {
            assert.isFalse(await this._publicKey.isPrivate);
        });
        it('isEncrypted of publicKey is False', async () => {
            assert.isFalse(await this._publicKey.isEncrypted);
        });
        it('Key type of publicKey is EC', async () => {
            assert.equal(await this._publicKey.keyType, 'EC');
        });
        it('isPrivate of privateKey is True', async () => {
            assert.isTrue(await this._privateKey.isPrivate);
        });
        it('isEncrypted of privateKey is True', async () => {
            assert.isTrue(await this._privateKey.isEncrypted);
        });
        it('Decrypt privateKey with wrong password', async () => {
            //todo
            assert.throws(this._privateKey.decrypt('just secret'),'FailedToDecryptNode: DecryptionFailure')

        });
        it('Decrypt privateKey with password', async () => {
            assert.isTrue(await this._privateKey.decrypt('top secret'));
        });
        it('Key type of privateKey is EC', async () => {
            assert.equal(await this._privateKey.keyType, 'EC');
        });
        it('Export privateKey as publicKey', async () => {
            assert.equal((await this._privateKey.export('pem', {outputPublic: true})).replace(/\n$/, ""),this._pemPublicKey.replace(/\n$/, ""))
        })
        it('Encrypt privateKey with password', async () => {
            assert.isTrue(await this._privateKey.encrypt('top secret'));
        });
        it('Export privateKey with password', async () => {
            console.info(typeof await this._privateKey.der)
            assert.equal(await this._privateKey.der, true);
        });
        it('Sign String with encrypted private key and verify with public key', async () => {
            //console.info(crypto.getHashes() )
            const value = 'My text to encrypt and verify'
            const privateKey = await this._privateKey.pem;
            var signature = crypto.createSign("RSA-SHA256").
                update(value).
                sign({key: privateKey,
                    passphrase: 'top secret',
                    padding:crypto.constants.RSA_PKCS1_PSS_PADDING, 
                    saltLength:10}, "base64");
            const publicKey = await this._publicKey.pem;
            var verified = crypto.createVerify("RSA-SHA256")
                .update(value)
                .verify({key: publicKey, 
                    padding:crypto.constants.RSA_PKCS1_PSS_PADDING, 
                    saltLength:10}, 
                    signature, "base64");
            assert.isTrue(verified);
        })
    })
  });
});
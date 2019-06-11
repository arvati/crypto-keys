const assert = require('chai').assert;
const crypto = require('crypto');
const cryptoKeys = require('../lib')

describe('Node Module for Cryptographic Key Utilities in JavaScript', () => {

    var self_ = this;
    before('Function to create KeyPair with node.js crypto', () => {
        self_.getKeyPair = (type = "ec", options = {modulusLength: 4096, namedCurve: 'secp256k1', publicKeyEncoding: {type: 'spki', format: 'pem'}, privateKeyEncoding: {type: 'pkcs8', format: 'pem'}}) => {
            return {publicKey, privateKey} = crypto.generateKeyPairSync(type, options)
        }
    })

    it('Default Key Pair generation using node crypto', () => {
    // This will only work with higher versions of nodejs >=10
    const {publicKey, privateKey} = self_.getKeyPair()
    self_.publicKey = publicKey
    self_.privateKey = privateKey
    assert.isString(publicKey,'public key is not a string');
    assert.isString(privateKey,'private key is not a string');
    })

    it.skip('Generating RSA key pair ...', () => {
        this._privateKey = new cryptoKeys('create', {type:'rsa', modulusLength:2048, publicExponent:65537});
        this._publicKey = new cryptoKeys('jwk', this._privateKey.export('jwk', {outputPublic: true}) )
        this._privateKey.encrypt('top secret')
        assert.isObject(this._publicKey,'public key is not a object');
        assert.isObject(this._privateKey, 'private key is not a object');
    }).timeout(10000);

    it('Generating EC key pair ...', () => {
        // this._privateKey = new cryptoKeys('create', {type:'ec', namedCurve:'P-256K'});
        // this._privateKey.encrypt('top secret')

        privateKey = new cryptoKeys('pem', self_.privateKey);
        publicKey = cryptoKeys.getPublicKey(privateKey)
        assert.isObject(privateKey,'private key is not a object');
        assert.isTrue(publicKey instanceof cryptoKeys, 'public key is not a cryptoKeys object');
    })

    it.skip('Export RSA privateKey as publicKey', () => {
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
        const {publicKey, privateKey} = self_.getKeyPair('rsa', options)
        key = new cryptoKeys('pem', privateKey);
        key.decrypt('top secret')
        assert.equal((key.export('pem', {outputPublic: true})).replace(/\n$/, ""),publicKey.replace(/\n$/, ""))
    })

    it.skip('Export EC privateKey as publicKey', () => {
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
        const {publicKey, privateKey} = self_.getKeyPair('ec', options)
        key = new cryptoKeys('pem', privateKey);
        key.decrypt('top secret')
        assert.equal((key.export('pem', {outputPublic: true})).replace(/\n$/, ""),publicKey.replace(/\n$/, ""))
    })

},true);
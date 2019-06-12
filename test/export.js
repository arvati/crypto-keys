const assert = require('chai').assert;
const crypto = require('crypto');
const cryptoKeys = require('../lib')

describe('Test ', () => {
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
    

},true);
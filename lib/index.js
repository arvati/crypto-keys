// Guide for JSDoc : https://github.com/jsdoc2md/jsdoc-to-markdown/wiki
// And this: https://github.com/shri/JSDoc-Style-Guide
// And this: https://devdocs.io/jsdoc/
// And this: https://google.github.io/styleguide/jsguide.html#jsdoc
// Great Guide: https://make.wordpress.org/core/handbook/best-practices/inline-documentation-standards/javascript/

/** 
@fileOverview Main file for crypto-keys module.
@author       Ademar Arvati
@requires     NPM:asn1.js
@requires     NPM:des.js
@requires     NPM:elliptic
@requires     NPM:lodash.clonedeep
@requires     ./jsbn.js:jsbn
@description  Node.js javascript tool to generate ,encrypt and decrypt RSA and EC keys formated as PEM / DER.
@module       crypto-keys
@typicalname  cryptoKeys
@license      MIT
@example
const cryptoKeys = require('crypto-keys')
*/

const {toJwkFrom, 
  fromJwkTo, 
  newRsaToJwk, 
  newEcToJwk, 
  getJwkType, 
  isAsn1Public, 
  isAsn1Encrypted, 
  pemToBin, 
  binToPem, 
  asn1enc_toJwk, 
  asn1ec_fromJWK, 
  asn1rsa_fromJwk,
  SubjectPublicKeyInfo} = require('./crypto-key-utils')
const cloneDeep = require('lodash.clonedeep');


// https://github.com/junkurihara/jscu/tree/develop/packages/js-crypto-key-utils

/**
Key Class.
@description Crypto-Keys class.
@alias module:crypto-keys
*/
class Key {
/**
Create a Key.
@description Import or Create a Crypto-Keys Class.
@param {string} format - Format of key to import ('der', 'pem' or 'jwk') or 'create' to create a new private key
@param {(string|Uint8Array|jwk|Object)} key - String for pem key, Uint8Array for der key, {jwk} for jwk key or to create new key.
@param {string} [key.type=ec] - 'rsa' or 'ec' for key type to be created
@param {string} [key.namedCurve=P-256K] - Curve for EC type key creation 'P-256', 'P-384', 'P-521', 'P-256K'
@param {integer} [key.modulusLength=2048] - Modulus Length for RSA type key creation
@param {integer} [key.publicExponent=65537] - Public Exponent for RSA type key creation
@param {string} [key.passphrase] - Passphrase to encrypt private key creation
@param {string} [key.algorithm=pbes2] - Used for creation of encrypted private key, choose from 'pbeWithMD5AndDES-CBC', 'pbeWithSHA1AndDES-CBC', 'pbes2'
@param {integer} [key.iterationCount=2048] - Used for creation of encrypted private key, iteration count to use for salt algorithm
@param {string} [key.cipher=aes256-cbc] - Used for creation of encrypted private key, Cipher when algorithm is 'pbes2', choose from 'des-ede3-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc'
@param {string} [key.prf=hmacWithSHA256] - Used for creation of encrypted private key, Prf when algorithm is 'pbes2', choose from 'hmacWithSHA1', 'hmacWithSHA256', 'hmacWithSHA384', 'hmacWithSHA512'
@example
Creating a new private key
```js
privateKey = new cryptoKeys('create', {type:'rsa', modulusLength:2048, publicExponent:65537});
```
Importing a pem public key (string)
```js
key = new cryptoKeys('pem', publicKey);
```
*/
    constructor(format, key){
        var localKey = cloneDeep(key);
        this._jwk = {};
        this._der = null;
        this._current = { jwk: false, der: false};
        if(format === 'jwk'){
            this._setJwk(localKey);
          }
        else if (format === 'der' || format === 'pem'){
            if(format === 'der' && !(localKey instanceof Uint8Array)) throw new Error('Der Key Must Be Uint8Array');
            if(format === 'pem' && (typeof localKey !== 'string')) throw new Error('Pem Key Must Be String');
            this._setAsn1(localKey, format);
            if (!this._isEncrypted && this._type === 'public') {
                this._setJwk(toJwkFrom('der', this._der))
            }
        }
        else if (format === 'create') {
          if(!(localKey instanceof Object)) localKey = { type: 'ec'}
          var newKey = {};
          if (localKey.type ==='rsa') {
            newKey = newRsaToJwk(localKey.modulusLength, localKey.publicExponent)
          }
          else if (!localKey.type || localKey.type === 'ec') {
            newKey = newEcToJwk(localKey.namedCurve)
          }
          this._setJwk(newKey);
          //todo: include option to encrypt private key
        } else throw new Error('UnsupportedType');
        
    }
/**
@description Saves jwk key and related info as type, encryption into this class instance.
@private
*/
    _setJwk(jwkey){
        this._type = getJwkType(jwkey); // this also check key format
        this._jwk = jwkey;
        if (this._isEncrypted) this._der = null;
        this._isEncrypted = false;
        this._setCurrentStatus();
    }
/**
@description Saves pem or der key and related info as type, encryption into this class instance.
@private
*/
    _setAsn1(asn1key, format){
        this._der = (format === 'pem') ? pemToBin(asn1key): asn1key;
        this._type = (isAsn1Public(this._der, 'der')) ? 'public' : 'private'; // this also check key format
        this._isEncrypted = isAsn1Encrypted(this._der, 'der');
        this._setCurrentStatus();
    }
/**
@description True or False for _current jwk and der info into this class instance.
@private
*/
    _setCurrentStatus() {
        this._current.jwk = (
            typeof this._jwk.kty === 'string'
            && (this._jwk.kty === 'RSA' || this._jwk.kty === 'EC')
        );
        this._current.der = (
          typeof this._der !== 'undefined'
          && this._der instanceof Uint8Array
          && this._der.length > 0
        );
    }
/**
Export Key as format.
@description Export Crypto-Keys as specified format.
@param {string} [format=jwk] - Format of key to export ('der', 'pem' or 'jwk')
@param {Object} [options={}] - Options to export key into format only with decrypted keys
@param {Object} [options.encryptParams={}] - Options to export encrypted prvate key for 'pem' and 'der' formats
@param {string} [options.encryptParams.passphrase] - Passphrase to encrypt private key
@param {string} [options.encryptParams.algorithm=pbes2] - if 'pbes2' only pbkdf2 and salt length of 8 is available, choose from 'pbeWithMD5AndDES-CBC', 'pbeWithSHA1AndDES-CBC', 'pbes2'
@param {integer} [options.encryptParams.iterationCount=2048] - Iteration count to use for salt algorithm
@param {string} [options.encryptParams.cipher=aes256-cbc] - Cipher when algorithm is 'pbes2', choose from 'des-ede3-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc'
@param {string} [options.encryptParams.prf=hmacWithSHA256] - Prf when algorithm is 'pbes2', choose from 'hmacWithSHA1', 'hmacWithSHA256', 'hmacWithSHA384', 'hmacWithSHA512'
@param {boolean} [options.outputPublic] - True to Export public key from private Key or undefined/False to maintain actual format
@param {boolean} [options.compact=false] - Export compact key for 'EC' type keys
@returns {(string|Uint8Array|jwk)} - Key in 'der', 'pem' or 'jwk' format
*/
    export(format = 'jwk', options={}){
        // global assertion
        if(['pem', 'der', 'jwk'].indexOf(format) < 0) throw new Error('Unsupported Format');
        // return 'as is' without passphrase when nothing is given as 'options'
        // only for the case to export der key from der key (considering encrypted key). expect to be called from getter
        if(this._isEncrypted && this._type === 'private'){
          if((format === 'der' || format === 'pem') && Object.keys(options).length === 0 && this._current.der) {
            return (format === 'pem') ? binToPem(this._der, 'encryptedPrivate') : this._der;
          }
          else throw new Error('Decryption Required');
        }
        // first converted to jwk
        let jwkey;
        if (this._current.jwk) {
          jwkey = this._jwk;
        }
        else if (this._current.der) {
          jwkey = toJwkFrom('der', this._der);
        }
        else throw new Error('Invalid Status');

        this._setJwk(jwkey); // store jwk if the exiting private key is not encrypted

        // then export as the key in intended format
        if (format === 'der' || format === 'pem') {
          if(typeof options.encryptParams === 'undefined') options.encryptParams = {};
          return fromJwkTo(format, jwkey, {
            outputPublic: options.outputPublic,
            compact: options.compact,
            //passphrase: options.encryptParams.passphrase,
            encryptParams: options.encryptParams
          });
        } else if (format === 'jwk' && (jwkey.kty === 'EC' || jwkey.kty === 'RSA')) {
          var localKey = cloneDeep(jwkey);
          if (options.outputPublic) {
            delete localKey.d
            delete localKey.p
            delete localKey.q
            delete localKey.dp
            delete localKey.dq
            delete localKey.qi
          }
          return localKey
        } else throw new Error('Unsupported key Type');
    }
/**
Turn Private Key into Public.
@description Turn Private Key into Public Key.
@chainable
@param {string} [passphrase] - Passphrase to decrypt private key, needed if encrypted
@returns {Class} this - Key for chainning
*/
    makePublic(passphrase) {
      if(this._type === 'private' && this._current.der){
        if (typeof passphrase === 'undefined') passphrase = ''
        var jwkey = asn1enc_toJwk(this._der, 'der', {outputPublic: true, passphrase});
        this._setJwk(jwkey);
        //done: need to update _der key from private to public
        let decoded;
        if (this._jwk.kty === 'EC') {
          decoded = asn1ec_fromJWK(this._jwk, 'public', false);
        } else if (this._jwk.kty === 'RSA'){
          decoded = asn1rsa_fromJwk(this._jwk, 'public');
        }
        this._der = new Uint8Array(SubjectPublicKeyInfo.encode(decoded, 'der'))
        this._setAsn1(this._der,'der')
        return this
      } else if (this._isEncrypted) throw new Error('Decryption Required');
      else if(!this._current.jwk || this._current.der) throw new Error('Unsupported key Type');
      else if(this._type === 'private') {
          delete this._jwk.d
          delete this._jwk.p
          delete this._jwk.q
          delete this._jwk.dp
          delete this._jwk.dq
          delete this._jwk.qi
          this._type = getJwkType(this._jwk) // checks if is really public
          this._der = null;
      } else throw new Error('Already Public Key')
      return this
    }
/**
Encrypt Private Key.
@description Encrypt Private Key using default parameters.
@chainable
@param {string} passphrase - Passphrase to encrypt private key
@param {Object} [options={}] - Options to encrypt private key
@param {string} [options.algorithm=pbes2] - if 'pbes2' only pbkdf2 and salt length of 8 is available, choose from 'pbeWithMD5AndDES-CBC', 'pbeWithSHA1AndDES-CBC', 'pbes2'
@param {integer} [options.iterationCount=2048] - Iteration count to use for salt algorithm
@param {string} [options.cipher=aes256-cbc] - Cipher when algorithm is 'pbes2', choose from 'des-ede3-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc'
@param {string} [options.prf=hmacWithSHA256] - Prf when algorithm is 'pbes2', choose from 'hmacWithSHA1', 'hmacWithSHA256', 'hmacWithSHA384', 'hmacWithSHA512'
@returns {Class} this - Key for chainning
*/
    encrypt (passphrase,options={algorithm: 'pbes2', iterationCount: 2048, cipher: 'aes256-cbc', prf: 'hmacWithSHA256'}){
        if(this._isEncrypted) throw new Error('Already Encrypted');
        const encryptParams = Object.assign(options,{passphrase})
        this._setAsn1(this.export('der', {encryptParams}), 'der');
        return this;
    }
/**
Decrypt Private Key.
@description Decrypt Private Key using default parameters.
@chainable
@param {string} passphrase - Passphrase to decrypt private key
@returns {Class} this - Key for chainning
*/
    decrypt (passphrase){
        if(!this._isEncrypted) throw new Error('Not Encrypted');
        let jwkey;
        if(this._current.der && typeof passphrase === 'string'){
          jwkey = toJwkFrom('der', this._der, {passphrase}); // type is not specified here to import jwk
        }
        else throw new Error('Failed to Decrypt');
        this._setJwk(jwkey);
        return this;
    }
/**
Get Jwk Thumbprint.
@description Get Jwk Thumbprint of decrypted keys.
@param {string} [alg=SHA-256] - Hash algorithm, choose from 'SHA-256','SHA-384','SHA-512' and 'SHA-1, 'MD5' that SHOULD NOT USE
@param {string} [output=binary] - Output Format 'binary', 'hex', 'base64'
@returns {(Uint8Array|string)} - Jwk Thumbprint of the key in format
*/
    getJwkThumbprint(alg='SHA-256', output='binary'){
        if(this._isEncrypted) throw new Error('Decryption Required');
        return getJwkThumbprint(this.export('jwk'), alg, output);
    }
/**
Get Jwk key type using password if needed.
@description Get Jwk key type of decrypted keys.
@param {string} [passphrase] - Passphrase to decrypt private key, needed if encrypted
@returns {string} - key type 'EC' or 'RSA'
*/
    getKeyType(passphrase){
        let jwkey = {};
        if (this.isEncrypted && typeof passphrase === 'undefined') throw new Error('Decryption Required');
        else if (this.isEncrypted) {
          jwkey = cloneDeep(this).decrypt(passphrase).export('jwk');
        }
        else jwkey = this.export('jwk');
        return jwkey.kty
    }
/**
Get Jwk key type.
@description Get Jwk key type of decrypted keys.
@param {string} [passphrase] - Passphrase to decrypt private key, needed if encrypted
@returns {string} - key type 'EC' or 'RSA'
*/
    get keyType(){
      if (this.isEncrypted) throw new Error('Decryption Required');
      return this.getKeyType();
    }
/**
Get Jwk Thumbprint.
@description Get Jwk Thumbprint of the decrypted key with default parameters alg='SHA-256', output='binary'.
@returns {} Jwk Thumbprint of the key
*/
    get jwkThumbprint(){
        return this.getJwkThumbprint();
    }
    get isEncrypted(){ return this._isEncrypted; }
    get isPrivate(){ return this._type === 'private'; }
    get der(){ return this.export('der'); }
    get pem(){ return this.export('pem'); }
    get jwk(){ return this.export('jwk'); }

/**
Get a Public Key from a Private Key.
@description Get a Public Key from a Private Key (preserving private key)
@chainable
@static
@param {Class} this - Private Key to get Public Key from.
@param {string} [passphrase] - Passphrase to decrypt private key, needed if encrypted
@returns {Class} this - Public Key for chainning
*/
    static getPublicKey(privateKey, passphrase) {
      if (!privateKey.isPrivate) throw new Error('Already Public Key');
      if (privateKey.isEncrypted && typeof passphrase === 'undefined') throw new Error('Decryption Required');
      var localKey = cloneDeep(privateKey);
      return localKey.makePublic(passphrase) 
    }
/*
@param {Object} [options={}] - Options for private and public key creation.
@param {string} [options.type=ec] - 'rsa' or 'ec' for key type to be created
@param {string} [options.namedCurve=P-256K] - Curve for EC type key creation 'P-256', 'P-384', 'P-521', 'P-256K'
@param {integer} [options.modulusLength=2048] - Modulus Length for RSA type key creation
@param {integer} [options.publicExponent=65537] - Public Exponent for RSA type key creation
@param {string} [options.passphrase] - Passphrase to encrypt private key creation
@param {string} [options.algorithm=pbes2] - Used for creation of encrypted private key, choose from 'pbeWithMD5AndDES-CBC', 'pbeWithSHA1AndDES-CBC', 'pbes2'
@param {integer} [options.iterationCount=2048] - Used for creation of encrypted private key, iteration count to use for salt algorithm
@param {string} [options.cipher=aes256-cbc] - Used for creation of encrypted private key, Cipher when algorithm is 'pbes2', choose from 'des-ede3-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc'
@param {string} [options.prf=hmacWithSHA256] - Used for creation of encrypted private key, Prf when algorithm is 'pbes2', choose from 'hmacWithSHA1', 'hmacWithSHA256', 'hmacWithSHA384', 'hmacWithSHA512'
*/
    static generateKeyPair(format, options={}) {
//todo: create private and public
//todo: make possible to create encrypted private keys
// use same options of create except for format
// return {publicKey, privateKey} if format especified in der, pem or jwk or as cryptoKeys for chainning if not
    }
}

module.exports = Key;
// Guide for JSDoc : https://github.com/jsdoc2md/jsdoc-to-markdown/wiki
// And this: https://github.com/shri/JSDoc-Style-Guide
// And this: https://devdocs.io/jsdoc/
// And this: https://google.github.io/styleguide/jsguide.html#jsdoc

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

const asn = require('asn1.js');
const BN = asn.bignum;
const des = require('des.js');
const crypto = require('crypto');
const Ec = require('elliptic').ec;
const cloneDeep = require('lodash.clonedeep');
const {BigInteger, SecureRandom} = require('./jsbn.js');

// https://github.com/junkurihara/jscu/tree/develop/packages/js-crypto-key-utils

/**
@description Key class.
@alias module:crypto-keys
*/
class Key {
/**
@description Import or Create a Key.
@param {string} format - Format of key to import ('der', 'pem' or 'jwk') or 'create' to create a new private key
@param {(string|Uint8Array|jwk|Object)} key - String for pem key, Uint8Array for der key, {jwk} for jwk key or to create new key.
@param {string} [key.type=ec] - 'rsa' or 'ec' for key type to be created
@param {string} [key.namedCurve=P-256K] - Curve for EC type key creation 'P-256', 'P-384', 'P-521', 'P-256K'
@param {integer} [key.modulusLength=2048] - Modulus Length for RSA type key creation
@param {integer} [key.publicExponent=65537] - Public Exponent for RSA type key creation
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
        this._type = (isAsn1Public(asn1key, format)) ? 'public' : 'private'; // this also check key format
        this._isEncrypted = isAsn1Encrypted(asn1key, format);
        this._der = (format === 'pem') ? pemToBin(asn1key): asn1key;
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
@description Export Key as format.
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
        if(this._current.jwk){
          jwkey = this._jwk;
        }
        else if(this._current.der) {
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
          this._type = getJwkType(jwkey) // checks if is reaaly public
          this._der = null;
      } else throw new Error('Already Public Key')
      return this
    }
/**
@description Encrypt Private Key using default parameters.
@chainable
@param {string} passphrase - Passphrase to encrypt private key
@returns {Class} this - Key for chainning
*/
    encrypt (passphrase){
        if(this._isEncrypted) throw new Error('Already Encrypted');
        const options = {encryptParams: {passphrase}};
        this._setAsn1(this.export('der', options), 'der');
        return this;
    }
/**
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
@description Get Jwk Thumbprint of decrypted keys
@param {string} [alg=SHA-256] - Hash algorithm, choose from 'SHA-256','SHA-384','SHA-512' and 'SHA-1, 'MD5' that SHOULD NOT USE
@param {string} [output=binary] - Output Format 'binary', 'hex', 'base64'
@returns {(Uint8Array|string)} - Jwk Thumbprint of the key in format
*/
    getJwkThumbprint(alg='SHA-256', output='binary'){
        if(this._isEncrypted) throw new Error('Decryption Required');
        return getJwkThumbprint(this.export('jwk'), alg, output);
    }
/**
@description Get Jwk key type of decrypted keys
@returns {string} - key type 'EC' or 'RSA'
*/
    get keyType(){
        if(this._isEncrypted) throw new Error('Decryption Required');
        const jwkey = this.export('jwk');
        return jwkey.kty
    }
/**
@description Get Jwk Thumbprint of the decrypted key with default parameters alg='SHA-256', output='binary'
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
@description Get a Public Key from a Private Key (preserving private key)
@chainable
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
}

// ******************************************************
// ***************** Private Methods ********************
// ******************************************************

const getJwkType = (jwkey) => {
    if(jwkey.kty === 'EC'){
      if (jwkey.x && jwkey.y && jwkey.d) return 'private';
      else if (jwkey.x && jwkey.y) return 'public';
      else throw new Error('Invalid EC Key');
    }
    else if (jwkey.kty === 'RSA'){
      if (jwkey.n && jwkey.e && jwkey.d && jwkey.p && jwkey.q && jwkey.dp && jwkey.dq && jwkey.qi) return 'private';
      else if (jwkey.n && jwkey.e) return 'public';
      else throw new Error('Invalid RSA Key');
    }
    else throw new Error('Unsupported JWK Type');
};
const isAsn1Public = (key, format='pem') => {
    let keyType;
    try { 
      keyType = getAsn1KeyType(key, format);
    } catch(e) {
      console.warn(e)
      return false;
    }
    return (keyType === 'public');
};
const isAsn1Encrypted = (key, format='pem') => {
    let keyType;
    try { 
      keyType = getAsn1KeyType(key, format);
    } catch(e) {
      console.warn(e)
      return false;
    }
    return keyType === 'encryptedPrivate';
};
const getAsn1KeyType = (key, format='pem') => {
    // Peel the pem strings
    // done: no reason of 'private' param in pemToBin function below
    const binKey = (format === 'pem') ? pemToBin(key) : key;
    const decoded = KeyStructure.decode(Buffer.from(binKey), 'der');
    if (decoded.type === 'encryptedPrivateKeyInfo') return 'encryptedPrivate';
    else if (decoded.type === 'oneAsymmetricKey') return 'private';
    else if (decoded.type === 'subjectPublicKeyInfo') return 'public';
    else throw new Error('Not Spki Nor Pkcs8 Key');
};
const getSec1KeyType = (sec1key, namedCurve)=> {
    let format;
    if (sec1key instanceof Uint8Array) format = 'binary';
    else if (typeof sec1key === 'string') format = 'string';
    else throw new Error('Invalid Object Type');
    const binKey = (format === 'string') ? hexStringToArrayBuffer(sec1key): sec1key;
    const len = params.namedCurves[namedCurve].payloadSize;
    // original key type
    if (binKey.length <= len) return 'private';
    else if (
      (binKey.length === 2*len+1 && binKey[0] === 0x04)
      || (binKey.length === len+1 && (binKey[0] === 0x02 || binKey[0] === 0x03))
    ) return 'public';
    else throw new Error('Unsupported Key Structure');
};
const KeyStructure = asn.define('KeyStructure', function (){
    this.choice({
      subjectPublicKeyInfo: this.use(SubjectPublicKeyInfo),
      oneAsymmetricKey: this.use(OneAsymmetricKey),
      encryptedPrivateKeyInfo: this.use(EncryptedPrivateKeyInfo)
    });
});
const supportedPEMTypes = {
    'public': 'PUBLIC KEY',
    'private': 'PRIVATE KEY',
    'encryptedPrivate': 'ENCRYPTED PRIVATE KEY',
    'certificate': 'CERTIFICATE',
    'certRequest': 'CERTIFICATE REQUEST'
  };
const pemToBin = (keydataB64Pem) => {
    const keydataB64 = dearmorPem(keydataB64Pem);
    return decodeBase64(keydataB64);
};
const binToPem = (keydata, type) => {
    const keydataB64 = encodeBase64(keydata);
    return formatAsPem(keydataB64, type);
};
const dearmorPem = (str) => {
    // const beginRegExp = RegExp('^-----[\s]*BEGIN[^-]*KEY-----$', 'gm');
    // const endRegExp = RegExp('^-----[\s]*END[^-]*KEY-----$', 'gm');
    const beginRegExp = RegExp('^-----[\s]*BEGIN[^-]*-----$', 'gm');
    const endRegExp = RegExp('^-----[\s]*END[^-]*-----$', 'gm');
  
    // check if the object starts from 'begin'
    try {
      let dearmored = str.split(beginRegExp)[1].split(endRegExp)[0];
      dearmored = dearmored.replace(/\r?\n/g, '');
      return dearmored;
    } catch (e) {
      throw new Error('Invalid format as PEM');
    }
};
const formatAsPem = (str, type) => {
    if (Object.keys(supportedPEMTypes).indexOf(type) < 0) throw new Error('Unsupported type');
    const typeString = supportedPEMTypes[type];
    let finalString = `-----BEGIN ${typeString}-----\n`;
    while (str.length > 0) {
      finalString += `${str.substring(0, 64)}\n`;
      str = str.substring(64);
    }
    finalString = `${finalString}-----END ${typeString}-----`;
    return finalString;
};

const encodeBase64 = (data) => {
    let str = '';
    if (typeof data === 'string') str = data;
    else str = arrayBufferToString(data);
    return nodeBtoa(str);
};
const decodeBase64 = (str) => {
    const binary = nodeAtob(str);
    const data = stringToArrayBuffer(binary);
    return getAsciiIfAscii(data);
};
const nodeBtoa = (str) => {
    if(typeof Buffer === 'undefined') throw new Error('Unsupported Environment');
    let buffer;
    const type = Object.prototype.toString.call(str).slice(8, -1);
    const typedArrays = ['ArrayBuffer', 'TypedArray', 'Uint8Array', 'Int8Array', 'Uint8ClampedArray', 'Int16Array', 'Uint16Array', 'Int32Array', 'Uint32Array', 'Float32Array', 'Float64Array'];
    if (Buffer.isBuffer(str)) {
      buffer = str;
    }
    else if (typedArrays.indexOf(type) >= 0) {
      buffer = Buffer.from(str);
    }
    else {
      buffer = Buffer.from(str.toString(), 'binary');
    }
    return buffer.toString('base64');
};
const nodeAtob = (str) => {
    if(typeof Buffer === 'undefined') throw new Error('Unsupported Environment');
    return Buffer.from(str, 'base64').toString('binary');
};
const arrayBufferToString = (data) => {
    const bytes = sanitizeTypedArrayAndArrayBuffer(data);
    const arr = new Array(bytes.length);
    bytes.forEach( (x, i) => { arr[i] = x; });
    return String.fromCharCode.apply(null, arr);
  };
const stringToArrayBuffer = (str) => {
    const bytes = new Uint8Array(str.length);
    return bytes.map( (_x, i) => str.charCodeAt(i));
};
const hexStringToArrayBuffer = (str) => {
    const arr = [];
    const len = str.length;
    for (let i = 0; i < len; i += 2) arr.push(parseInt(str.substr(i, 2), 16));
    return new Uint8Array(arr);
};
const arrayBufferToHexString = (data) => {
    const arr = sanitizeTypedArrayAndArrayBuffer(data);
    let hexStr = '';
    for (let i = 0; i < arr.length; i++) {
      let hex = (arr[i] & 0xff).toString(16);
      hex = (hex.length === 1) ? `0${hex}` : hex;
      hexStr += hex;
    }
    return hexStr;
};
const encodeBase64Url = (data) => encodeBase64(data).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const decodeBase64Url = (str) => {
    str = str.replace(/-/g, '+').replace(/_/g, '/');  // str = str + "=".repeat(str.length % 4); // this sometimes causes error...
    return decodeBase64(str);
};

const sanitizeTypedArrayAndArrayBuffer = (data) => {
    if(data instanceof Uint8Array) return data;
    if (ArrayBuffer.isView(data) && typeof data.buffer !== 'undefined') { // TypedArray except Uint8Array
      return new Uint8Array(data.buffer);
    }
    else if (data instanceof ArrayBuffer) { // ArrayBuffer
      return new Uint8Array(data);
    }
    else throw new Error('Input must be an ArrayBuffer or a TypedArray');
};
const getAsciiIfAscii = (data) => {
    let flag = true;
    for (let i = 0; i < data.length; i++) {
      if (data[i] > 0x7e || (data[i] < 0x20 && data[i] !== 0x0d && data[i] !== 0x0a)) {
        flag = false;
        break;
      }
    }
    let returnData = null;
    if (flag) {
      returnData = '';
      for (let i = 0; i < data.length; i++) returnData += String.fromCharCode(data[i]);
    }
    else returnData = data;
    return returnData;
};
const pruneLeadingZeros = (array) => {
    if(!(array instanceof Uint8Array)) throw new Error('Non Uint8Array');
    let offset = 0;
    for (let i = 0; i < array.length; i++){
      if(array[i] !== 0x00) break;
      offset++;
    }
    const returnArray = new Uint8Array(array.length - offset);
    returnArray.set(array.slice(offset, array.length));
    return returnArray;
};
const appendLeadingZeros = (array, len) => {
    if(!(array instanceof Uint8Array)) throw new Error('Non Uint8Array');
    if(array.length > len) throw new Error('Invalid Length');
    const returnArray = new Uint8Array(len); // initialized with zeros
    returnArray.set(array, len - array.length);
    return returnArray;
};
const SubjectPublicKeyInfo = asn.define('SubjectPublicKeyInfo', function () {
    this.seq().obj(
      this.key('algorithm').use(AlgorithmIdentifier),
      this.key('subjectPublicKey').bitstr()
    );
});
const AlgorithmIdentifier = asn.define('AlgorithmIdentifier', function () {
    this.seq().obj(
        this.key('algorithm').objid(),
        this.key('parameters').optional().any()
    );
});
const OneAsymmetricKey = asn.define('OneAsymmetricKey', function () {
    this.seq().obj(
      this.key('version').use(Version),
      this.key('privateKeyAlgorithm').use(AlgorithmIdentifier),
      this.key('privateKey').octstr(),
      this.key('attributes').implicit(0).optional().any(),
      this.key('publicKey').implicit(1).optional().bitstr()
    );
});
const PBEParameter = asn.define('PBEParameter', function(){
    this.seq().obj(
      this.key('salt').octstr(8),
      this.key('iterationCount').int()
    );
});
const PBES2Params = asn.define('PBES2Params', function(){
    this.seq().obj(
      this.key('keyDerivationFunc').use(AlgorithmIdentifier),
      this.key('encryptionScheme').use(AlgorithmIdentifier)
    );
});
const PBKDF2Params = asn.define('PBKDF2Params', function(){
    this.seq().obj(
      this.key('salt').choice({
        'specified': this.octstr(),
        'otherSource': this.use(AlgorithmIdentifier)
      }),
      this.key('iterationCount').int(),
      this.key('keyLength').int().optional(),
      this.key('prf').use(AlgorithmIdentifier).def({
        algorithm: [1, 2, 840, 113549, 2, 7], // hmacWithSHA1
        parameters: Buffer.from([0x05, 0x00])
      })
    );
});
const PBES2ESParams = {
    'des-ede3-cbc': asn.define('DesEde3CbcParams', function(){
      this.octstr();
    }),
    'aes128-cbc': asn.define('Aes128CbcParams', function(){
      this.octstr();
    }),
    'aes192-cbc': asn.define('Aes192CbcParams', function(){
      this.octstr();
    }),
    'aes256-cbc': asn.define('Aes256CbcParams', function(){
      this.octstr();
    })
};
const ECParameters = asn.define('ECParameters', function() {
    this.choice({
      namedCurve: this.objid()
    });
});

const ECPrivateKey = asn.define('ECPrivateKey', function() {
    this.seq().obj(
      this.key('version').int(),
      this.key('privateKey').octstr(),
      this.key('parameters').explicit(0).objid().optional(), // https://github.com/indutny/elliptic/issues/43
      this.key('publicKey').explicit(1).bitstr().optional()
    );
});
/* 
const ECPrivateKey = asn.define('ECPrivateKey', function() {
  this.seq().obj(
    this.key('version').int(),
    this.key('privateKey').octstr(),
    this.key('parameters').explicit(0).any().optional(), // rfc suggested that this must be implemented
    this.key('publicKey').explicit(1).bitstr().optional() // rfc suggested that this must be implemented
  );
});
 */
const ECPrivateKeyAlt = asn.define('ECPrivateKey', function() {
  //todo: understand if this Alt could be different
    this.seq().obj(
      this.key('version').int(),
      this.key('privateKey').octstr(),
      // this.key('parameters').explicit(0).optional().any(), // rfc suggested that this must be implemented
      this.key('publicKey').explicit(1).bitstr().optional() // rfc suggested that this must be implemented
    );
});
const RSAPublicKey = asn.define('RSAPublicKey', function() {
    this.seq().obj(
      this.key('modulus').int(), // n
      this.key('publicExponent').int() // e
    );
  });
const RSAPrivateKey = asn.define('RSAPrivateKey', function(){
    this.seq().obj(
      this.key('version').int(), // 0
      this.key('modulus').int(), // n
      this.key('publicExponent').int(), // e
      this.key('privateExponent').int(), // d
      this.key('prime1').int(), // p
      this.key('prime2').int(), // q
      this.key('exponent1').int(), // d mod (p-1)
      this.key('exponent2').int(), // d mod (q-1)
      this.key('coefficient').int(), // (inverse of q) mod p
      this.key('otherPrimeInfos').optional().use(OtherPrimeInfos)
    );
});
const OtherPrimeInfos = asn.define('OtherPrimeInfos', function(){
    this.seqof(OtherPrimeInfo);
});
const OtherPrimeInfo = asn.define('OtherPrimeInfo', function(){
    this.seq().obj(
        this.key('prime').int(),
        this.key('exponent').int(),
        this.key('coefficient').int()
    );
});
const Version = asn.define('Version', function () {
    this.int();
});
const EncryptedPrivateKeyInfo = asn.define('EncryptedPrivateKeyInfo', function () {
    this.seq().obj(
      this.key('encryptionAlgorithm').use(AlgorithmIdentifier),
      this.key('encryptedData').octstr()
    );
});
const toJwkFrom = (input, key, options={}) => {
    // assertion
    if (['pem', 'der'].indexOf(input) < 0) throw new Error('Invalid Input Form');
    if (typeof options.outputPublic !== 'undefined' && typeof options.outputPublic !== 'boolean') throw new Error('outputPublic Must Be Boolean');
    // default values
    if ((input === 'der' || input === 'pem') && typeof options.passphrase === 'undefined') options.passphrase = '';
    // In the case of PEM
    if (input === 'der' || input === 'pem') {
      return asn1enc_toJwk(key, input, {outputPublic: options.outputPublic, passphrase: options.passphrase});
    }
    else throw new Error('Unsupported Conversion');
};
const asn1enc_toJwk = (key, format, {outputPublic, passphrase}) => {
    // Peel the pem strings
    const binKey = (format === 'pem') ? pemToBin(key) : key;
    // decode binary spki/pkcs8-formatted key to parsed object
    let decoded;
    try { 
      decoded = KeyStructure.decode(Buffer.from(binKey), 'der'); 
    } catch (e) { throw e }
    let type;
    if (decoded.type === 'subjectPublicKeyInfo'){
      type = 'public';
      decoded = decoded.value;
    }
    else {
      type = 'private';
      if(decoded.type === 'encryptedPrivateKeyInfo') decoded = decryptEncryptedPrivateKeyInfo(decoded.value, passphrase);
      else if (decoded.type === 'oneAsymmetricKey') decoded = decoded.value;
      else throw new Error('Unsupported Key Structure');
    }
    const keyTypes = getAlgorithmFromOid(
      (type === 'public') ? decoded.algorithm.algorithm : decoded.privateKeyAlgorithm.algorithm,
      params.publicKeyAlgorithms
    );

    //done : put outputPublic further on code
    if (typeof outputPublic !== 'boolean' && type === 'private') outputPublic = false;

    if(keyTypes.length < 1) throw new Error('Unsupported Key');
    if (keyTypes[0] === 'EC') {
      return asn1ec_toJWK(decoded, type, outputPublic);
    }
    else if (keyTypes[0] === 'RSA'){
      return asn1rsa_toJwk(decoded, type, outputPublic);
    }
    else throw new Error('Invalid Key Type');
};
const asn1rsa_toJwk = (decoded, type, outputPublic=false) => {
    if (type === 'public'){ // SPKI algorithm.algorithm.parameters is always null Ox0500 in ASN.1 as shown in the Section 2.3.1 https://tools.ietf.org/html/rfc3279
      // overwrite nested binary object as parsed object
      decoded.subjectPublicKey.data = RSAPublicKey.decode(decoded.subjectPublicKey.data, 'der');
      let modulus = decoded.subjectPublicKey.data.modulus;
      let publicExponent = decoded.subjectPublicKey.data.publicExponent;
      // convert n and e from BN
      // modulus n
      const nLen = modulus.byteLength();
      const len = (nLen % 128 === 0) ? nLen : nLen + (128 - (nLen % 128));
      modulus = new Uint8Array(modulus.toArray('be', len));
      // // publicExponent e;
      publicExponent = new Uint8Array(publicExponent.toArray('be', publicExponent.byteLength()));
      return {
        kty: 'RSA',
        n: encodeBase64Url(pruneLeadingZeros(modulus)), // prune leading zeros https://tools.ietf.org/html/rfc7518#section-6.3
        e: encodeBase64Url(pruneLeadingZeros(publicExponent))
      };
    }
    else if (type === 'private'){ // PKCS8 privateKeyAlgorithm.algorithm.parameters is always null Ox0500 in ASN.1 as shown in the Section 2.3.1 https://tools.ietf.org/html/rfc3279
      // overwrite nested binary object as parsed object
      decoded.privateKey = RSAPrivateKey.decode(decoded.privateKey, 'der');
      const privateKeyElems = {};
      privateKeyElems.modulus = decoded.privateKey.modulus;
      // calculate key length from modulus n
      const nLen = privateKeyElems.modulus.byteLength();
      const len = (nLen % 128 === 0) ? nLen : nLen + (128 - (nLen % 128)); // this is actual key length, e.g., 256 bytes
      // convert BN to Uint8Array
      privateKeyElems.modulus = new Uint8Array(privateKeyElems.modulus.toArray('be', len)); // n of length len
      privateKeyElems.publicExponent = new Uint8Array(
        decoded.privateKey.publicExponent.toArray( 'be', decoded.privateKey.publicExponent.byteLength() )
      ); // e of arbitrary small length
      privateKeyElems.privateExponent = new Uint8Array(decoded.privateKey.privateExponent.toArray('be', len)); // d of length len
      const keys = ['prime1', 'prime2', 'exponent1', 'exponent2', 'coefficient']; // elements of length len/2
      keys.forEach( (key) => {
        privateKeyElems[key] = new Uint8Array(decoded.privateKey[key].toArray('be', (len>>1) ));
      });
      // prune leading zeros JWW RSA private key: https://tools.ietf.org/html/rfc7517
      var jwk = {
        kty: 'RSA',
        n: encodeBase64Url(pruneLeadingZeros(privateKeyElems.modulus)),
        e: encodeBase64Url(pruneLeadingZeros(privateKeyElems.publicExponent))
      }
      // done: outputPublic = if false
      if (!outputPublic) 
        jwk = Object.assign(jwk,{
          d: encodeBase64Url(pruneLeadingZeros(privateKeyElems.privateExponent)),
          p: encodeBase64Url(pruneLeadingZeros(privateKeyElems.prime1)),
          q: encodeBase64Url(pruneLeadingZeros(privateKeyElems.prime2)),
          dp: encodeBase64Url(pruneLeadingZeros(privateKeyElems.exponent1)),
          dq: encodeBase64Url(pruneLeadingZeros(privateKeyElems.exponent2)),
          qi: encodeBase64Url(pruneLeadingZeros(privateKeyElems.coefficient))
        });
      return jwk
    }
}
const asn1ec_toJWK = (decoded, type, outputPublic=false) => {
    if (type === 'public'){ // SPKI
      decoded.algorithm.parameters = ECParameters.decode(decoded.algorithm.parameters, 'der'); // overwrite nested binary object as parsed object
      const octPubKey = new Uint8Array(decoded.subjectPublicKey.data); // convert oct key to jwk
      const namedCurves = getAlgorithmFromOid(decoded.algorithm.parameters.value, params.namedCurves);
      if(namedCurves.length < 1) throw new Error('Unsupported Curve');
      return octKeyToJwk(octPubKey, namedCurves[0], {outputPublic: true});
    }
    else if (type === 'private'){ // PKCS8
      decoded.privateKeyAlgorithm.parameters = ECParameters.decode(decoded.privateKeyAlgorithm.parameters, 'der');
      // Work around for optional private key parameter field.
      try { 
        decoded.privateKey = ECPrivateKey.decode(decoded.privateKey, 'der'); 
      } catch (e) { 
        console.warn(e)
        decoded.privateKey = ECPrivateKeyAlt.decode(decoded.privateKey, 'der'); 
      }
      const octPrivKey = new Uint8Array(decoded.privateKey.privateKey);
      const namedCurves = getAlgorithmFromOid(decoded.privateKeyAlgorithm.parameters.value, params.namedCurves);
      if(namedCurves.length < 1) throw new Error('Unsupported Curve');
      return octKeyToJwk(octPrivKey, namedCurves[0], {outputPublic});
    }
};
const newRsaToJwk = (bits = 2048, exp = 65537) => {
  // code from https://github.com/rzcoder/node-rsa/blob/master/src/libs/rsa.js
  // code from http://www-cs-students.stanford.edu/~tjw/jsbn/rsa2.js
  if (bits % 8 !== 0) throw Error('Key size must be a multiple of 8.');
  else B = bits
  const E = exp.toString(16)
  var rng = new SecureRandom();
  var qs = B >> 1;
  e = parseInt(E, 16);
  var ee = new BigInteger(E, 16);
  while (true) {
    while (true) {
        p = new BigInteger(B - qs, 1, rng);
        if (p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) === 0 && p.isProbablePrime(10))
            break;
    }
    while (true) {
        q = new BigInteger(qs, 1, rng);
        if (q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) === 0 && q.isProbablePrime(10))
            break;
    }
    if (p.compareTo(q) <= 0) {
        var t = p;
        p = q;
        q = t;
    }
    var p1 = p.subtract(BigInteger.ONE);
    var q1 = q.subtract(BigInteger.ONE);
    var phi = p1.multiply(q1);
    if (phi.gcd(ee).compareTo(BigInteger.ONE) === 0) {
        n = p.multiply(q);
        if (n.bitLength() < B) {
            continue;
        }
        d = ee.modInverse(phi);
        dmp1 = d.mod(p1);
        dmq1 = d.mod(q1);
        coeff = q.modInverse(p);
        break;
    }
  }
  const jwKey = { //https://www.rfc-editor.org/rfc/rfc7518.txt
    kty: 'RSA',
    n: encodeBase64Url(pruneLeadingZeros(new Uint8Array(n.toByteArray()))), //modulus
    e: encodeBase64Url(pruneLeadingZeros(new Uint8Array(ee.toByteArray()))), //publicExponent
    d: encodeBase64Url(pruneLeadingZeros(new Uint8Array(d.toByteArray()))), //privateExponent
    p: encodeBase64Url(pruneLeadingZeros(new Uint8Array(p.toByteArray()))), //prime1
    q: encodeBase64Url(pruneLeadingZeros(new Uint8Array(q.toByteArray()))), //prime2
    dp: encodeBase64Url(pruneLeadingZeros(new Uint8Array(dmp1.toByteArray()))), //exponent1
    dq: encodeBase64Url(pruneLeadingZeros(new Uint8Array(dmq1.toByteArray()))), //exponent2
    qi: encodeBase64Url(pruneLeadingZeros(new Uint8Array(coeff.toByteArray()))) //coefficient
  }
  return jwKey;
}
const newEcToJwk = (namedCurve = 'P-256K') => {
  if (Object.keys(params.namedCurves).indexOf(namedCurve) < 0) throw new Error('Unsupported Curve');
  const curve = params.namedCurves[namedCurve].indutnyName;
  const ec = new Ec(curve);
  const ecKey = ec.genKeyPair()
  const publicKey = new Uint8Array(ecKey.getPublic('array'));
  const privateKey = hexStringToArrayBuffer(ecKey.getPrivate('hex'));
  const len = params.namedCurves[namedCurve].payloadSize;
  const bufX = publicKey.slice(1, len+1);
  const bufY = publicKey.slice(len+1, len*2+1);
  const jwKey = { // https://www.rfc-editor.org/rfc/rfc7518.txt
    kty: 'EC',
    crv: namedCurve,
    x: encodeBase64Url(bufX), // oct to base64url
    y: encodeBase64Url(bufY),
    // ext: true
    d: encodeBase64Url(privateKey)
  }
  return jwKey;
}
const octKeyToJwk = (octkey, namedCurve, {outputPublic}) => {
    if (Object.keys(params.namedCurves).indexOf(namedCurve) < 0) throw new Error('Unsupported Curve');
    // original key type and check the key structure
    const orgType = getSec1KeyType(octkey, namedCurve);
    const type = (typeof outputPublic === 'boolean' && outputPublic) ? 'public' : orgType;
    // format conversion
    const binKey = (typeof octkey === 'string') ? hexStringToArrayBuffer(octkey): octkey;
    // instantiation
    const curve = params.namedCurves[namedCurve].indutnyName;
    const ec = new Ec(curve);
    // derive key object from binary key
    const ecKey = (orgType === 'public') ? ec.keyFromPublic(binKey): ec.keyFromPrivate(binKey);
    const publicKey = new Uint8Array(ecKey.getPublic('array'));
    const len = params.namedCurves[namedCurve].payloadSize;
    const bufX = publicKey.slice(1, len+1);
    const bufY = publicKey.slice(len+1, len*2+1);
    const jwKey = { // https://www.rfc-editor.org/rfc/rfc7518.txt
      kty: 'EC',
      crv: namedCurve,
      x: encodeBase64Url(bufX), // oct to base64url
      y: encodeBase64Url(bufY)
      // ext: true
    };
    if(type === 'private'){
      // octkey is exactly private key if type is private.
      jwKey.d = encodeBase64Url(binKey);
    }
    return jwKey;
};
const fromJwkTo = (output = 'pem', jwkey, options={}) => {
    // assertion
    if (['pem', 'der'].indexOf(output) < 0) throw new Error('Invalid Output Form');
    if (typeof jwkey !== 'object') throw new Error('Invalid JWK As Object');
    if (jwkey.kty !== 'EC' && jwkey.kty !== 'RSA') throw new Error('Unsupported Key Type');
    if (typeof options.outputPublic !== 'undefined' && typeof options.outputPublic !== 'boolean') throw new Error('outputPublic Must Be Boolean');
    // default values
    if (jwkey.key === 'EC' && typeof options.compact !== 'boolean') options.compact = false;
    if (typeof options.encryptParams === 'undefined') options.encryptParams = {};
    if ((output === 'der' || output === 'pem') && typeof options.encryptParams.passphrase === 'undefined') options.encryptParams.passphrase = '';
    // In the case of PEM/DER
    if (output === 'der' || output === 'pem') {
      return asn1enc_fromJwk(
        jwkey, output,
        {outputPublic: options.outputPublic, compact: options.compact, encOptions: options.encryptParams }
      );
    }
    else throw new Error('Unsupported Conversion');
};
const asn1enc_fromJwk = (jwkey, format, {outputPublic, compact=false, encOptions}) => {
    const orgType = getJwkType(jwkey);
    let type = (typeof outputPublic === 'boolean' && outputPublic) ? 'public' : orgType;
    let decoded;
    if (jwkey.kty === 'EC') {
      decoded = asn1ec_fromJWK(jwkey, type, compact);
    }
    else if (jwkey.kty === 'RSA'){
      decoded = asn1rsa_fromJwk(jwkey, type);
    }
    let binKey;
    if (type === 'public') {
      binKey = SubjectPublicKeyInfo.encode(decoded, 'der');
    }
    else {
      binKey = OneAsymmetricKey.encode(decoded, 'der');
      if(typeof encOptions.passphrase !== 'undefined' && encOptions.passphrase.length > 0){
        binKey = encryptEncryptedPrivateKeyInfo(binKey, encOptions);
        type = 'encryptedPrivate';
      }
    }
    binKey = new Uint8Array(binKey);
    return (format === 'pem') ? binToPem(binKey, type) : binKey;
};
const asn1ec_fromJWK = (jwk, type, compact=false) => {
    if (Object.keys(params.namedCurves).indexOf(jwk.crv) < 0) throw new Error('Unsupported Curve');
    const octetPublicKey = octKeyFromJwk(jwk, {outputFormat: 'binary', outputPublic: true, compact});
    const publicKeyAlgorithmOid = params.publicKeyAlgorithms['EC'].oid;
    const publicKey = {unused: 0, data: Array.from(octetPublicKey)};//Buffer.from(octkeyObj.publicKey)};
    const parameters = ECParameters.encode({ type: 'namedCurve', value: params.namedCurves[jwk.crv].oid }, 'der');
    const algorithm = { algorithm: publicKeyAlgorithmOid, parameters };
    const decoded = {};
    if (type === 'public'){ // SPKI
      decoded.subjectPublicKey = publicKey;
      decoded.algorithm = algorithm;
    }
    else if (type === 'private') { // PKCS8
      const octetPrivateKey = octKeyFromJwk(jwk, {outputFormat: 'binary', outputPublic: false, compact});
      decoded.version = 0; // no public key presents for v2 (0)
      decoded.privateKeyAlgorithm = algorithm;
      //optionalParameters = params.namedCurves[jwk.crv].oid // https://github.com/indutny/elliptic/issues/43
      optionalParameters = undefined // to be compatible with node crypto der key 
      decoded.privateKey = ECPrivateKey.encode({
        version: 1,
        privateKey: Array.from(octetPrivateKey), //Buffer.from(octkeyObj.privateKey),
        parameters: optionalParameters,
        publicKey
      }, 'der');
    }
    return decoded;
};
const octKeyFromJwk = (jwkey, {outputPublic, outputFormat='binary', compact=false}) => {
    // original key type
    const orgType = getJwkType(jwkey);
    const type = (typeof outputPublic === 'boolean' && outputPublic) ? 'public' : orgType;
    if(type === 'public'){
      const bufX = decodeBase64Url(jwkey.x);
      const bufY = decodeBase64Url(jwkey.y);
      let publicKey;
      if(compact){
        // compressed form http://www.secg.org/SEC1-Ver-1.0.pdf
        publicKey = new Uint8Array(bufX.length + 1);
        publicKey[0] = 0xFF & ( (0x01 & bufY.slice(-1)[0]) + 0x02 );
        publicKey.set(bufX, 1);
      }
      else {
        // uncompressed form
        publicKey = new Uint8Array(bufX.length + bufY.length + 1);
        publicKey[0]=0xFF & 0x04;
        publicKey.set(bufX, 1);
        publicKey.set(bufY, bufX.length+1);
      }
      return (outputFormat === 'string') ? arrayBufferToHexString(publicKey): publicKey;
    }
    else if (type === 'private'){
      if (!jwkey.d) throw new Error('InvalidKey');
      const bufD = decodeBase64Url(jwkey.d);
      return (outputFormat === 'string') ? arrayBufferToHexString(bufD) : bufD;
    }
};
const asn1rsa_fromJwk = (jwk, type) => {
    const publicKeyAlgorithmOid = params.publicKeyAlgorithms['RSA'].oid;
    // Parameters is always null Ox0500 in ASN.1 as shown in the Section 2.3.1 https://tools.ietf.org/html/rfc3279
    const parameters = Buffer.from([0x05, 0x00]);
    const algorithm = { algorithm: publicKeyAlgorithmOid, parameters };
    // to append leading zeros (pruned when making JWK) in order to make binary of intended bit length
    // https://tools.ietf.org/html/rfc7518#section-6.3
    const modulusBytes = decodeBase64Url(jwk.n);
    const nLen = modulusBytes.length;
    const modulusLength = (nLen % 128 === 0) ? nLen : nLen + (128 - (nLen % 128));
    const modulus = new asn.bignum(appendLeadingZeros(modulusBytes, modulusLength)); // JWA RFC
    const publicExponent = new asn.bignum(decodeBase64Url(jwk.e));
    const decoded = {};
    if(type === 'public'){ // SPKI
      decoded.subjectPublicKey = {
        unused: 0,
        data: RSAPublicKey.encode({ modulus, publicExponent  }, 'der')
      };
      decoded.algorithm = algorithm;
    }
    else if (type === 'private') { // PKCS8
      decoded.version = 0;  // no public key presents for v2 (0)
      decoded.privateKeyAlgorithm = algorithm;
      decoded.privateKey = RSAPrivateKey.encode({
        version: 0,
        modulus,
        publicExponent,
        privateExponent: new asn.bignum( appendLeadingZeros(decodeBase64Url(jwk.d), modulusLength)),
        prime1: new asn.bignum( appendLeadingZeros(decodeBase64Url(jwk.p), modulusLength)),
        prime2: new asn.bignum( appendLeadingZeros(decodeBase64Url(jwk.q), modulusLength)),
        exponent1: new asn.bignum( appendLeadingZeros(decodeBase64Url(jwk.dp), modulusLength)),
        exponent2: new asn.bignum( appendLeadingZeros(decodeBase64Url(jwk.dq), modulusLength)),
        coefficient: new asn.bignum( appendLeadingZeros(decodeBase64Url(jwk.qi), modulusLength))
      }, 'der');
    }
    return decoded;
}
const decryptEncryptedPrivateKeyInfo = (epki, passphrase) => {
    const decoded = {};
    // encryptionAlgorithm.algorithm
    decoded.encryptionAlgorithm = {
      algorithm: getAlgorithmFromOidStrict(epki.encryptionAlgorithm.algorithm, params.passwordBasedEncryptionSchemes)
    };
    if (decoded.encryptionAlgorithm.algorithm === 'pbes2') {
      decoded.encryptionAlgorithm.parameters = decodePBES2(epki.encryptionAlgorithm.parameters);
    }
    else {
      decoded.encryptionAlgorithm.parameters = PBEParameter.decode(epki.encryptionAlgorithm.parameters, 'der');
    }
    decoded.encryptedData = epki.encryptedData;
    // decrypt
    if(decoded.encryptionAlgorithm.algorithm === 'pbes2') {
      return decryptPBES2(decoded, passphrase);
    }
    else return decryptPBES1(decoded, passphrase);
};
const encryptPBES1 = (binKey, passphrase, algorithm, iterationCount) => {
    // pbkdf1
    const pBuffer = stringToArrayBuffer(passphrase);
    const salt = getRandomBytes(8); // defined as 8 octet
    const hash = params.passwordBasedEncryptionSchemes[algorithm].hash;
    const keyIv = pbkdf1(pBuffer, salt, iterationCount, 16, hash);
    const key = keyIv.slice(0, 8);
    const iv = keyIv.slice(8, 16);
    // decryption
    const encrypt = params.passwordBasedEncryptionSchemes[algorithm].encrypt;
    let out;
    // TODO: Other Encryption Scheme
    if(encrypt === 'DES-CBC') {
      const CBC = des.CBC.instantiate(des.DES);
      const ct = CBC.create({type: 'encrypt', key, iv});
      out = Buffer.from(ct.update(binKey).concat(ct.final()));
    }
    else throw new Error('Unsupported Encryption Algorithm');
    return {
      encryptionAlgorithm: {
        algorithm,
        parameters: {
          salt: Buffer.from(salt),
          iterationCount: new BN(iterationCount)
        }
      },
      encryptedData: out
    };
};
const decryptPBES1 = (decoded, passphrase) => {
    // pbkdf1
    const pBuffer = stringToArrayBuffer(passphrase);
    const salt = new Uint8Array(decoded.encryptionAlgorithm.parameters.salt);
    const hash = params.passwordBasedEncryptionSchemes[decoded.encryptionAlgorithm.algorithm].hash;
    const iterationCount = decoded.encryptionAlgorithm.parameters.iterationCount.toNumber();
    const keyIv = pbkdf1(pBuffer, salt, iterationCount, 16, hash);
    const key = keyIv.slice(0, 8);
    const iv = keyIv.slice(8, 16);
    // decryption
    const encrypt = params.passwordBasedEncryptionSchemes[decoded.encryptionAlgorithm.algorithm].encrypt;
    let out;
    // TODO: Other Encryption Scheme
    if(encrypt === 'DES-CBC') {
      const CBC = des.CBC.instantiate(des.DES);
      const ct = CBC.create({type: 'decrypt', key, iv});
      out = Buffer.from(ct.update(decoded.encryptedData).concat(ct.final()));
    }
    else throw new Error('Unsupported Encryption Algorithm');
    return OneAsymmetricKey.decode(out, 'der');
};
const decryptPBES2 = (decoded, passphrase) => {
    const kdf = decoded.encryptionAlgorithm.parameters.keyDerivationFunc;
    const eS = decoded.encryptionAlgorithm.parameters.encryptionScheme;
    // pbkdf2
    const keyLength = params.encryptionSchemes[eS.algorithm].keyLength; // get keyLength
    let key;
    if(kdf.algorithm === 'pbkdf2') {
      const pBuffer = stringToArrayBuffer(passphrase);
      if (kdf.parameters.salt.type !== 'specified') throw new Error('Unsupported Salt Source');
      const salt = new Uint8Array(kdf.parameters.salt.value);
      const iterationCount = kdf.parameters.iterationCount.toNumber();
      const prf = kdf.parameters.prf.algorithm;
      key = pbkdf2(pBuffer, salt, iterationCount, keyLength, params.pbkdf2Prfs[prf].hash);
    }
    else throw new Error('Unsupported KDF');
    // decryption
    // TODO other encryption schemes
    let out;
    if(eS.algorithm === 'des-ede3-cbc'){
      const iv = eS.parameters;
      const CBC = des.CBC.instantiate(des.EDE);
      const pt = CBC.create({ type: 'decrypt', key, iv });
      out = Buffer.from(pt.update(decoded.encryptedData).concat(pt.final()));
    }
    else if (eS.algorithm === 'aes128-cbc' || eS.algorithm === 'aes192-cbc'|| eS.algorithm === 'aes256-cbc'){
      const iv = new Uint8Array(eS.parameters);
      out = Buffer.from( jscaes_decrypt(
        new Uint8Array(decoded.encryptedData), key, {name: 'AES-CBC', iv}
      ));
    } else throw new Error('Unsupported Encryption Algorithm');
    return OneAsymmetricKey.decode(out, 'der');
};
const encryptEncryptedPrivateKeyInfo = (binKey, options = {passphrase:''}) => {
    // default params
    if(typeof options.algorithm === 'undefined') options.algorithm = 'pbes2';
    if(typeof options.iterationCount === 'undefined') options.iterationCount = 2048;
    if (options.algorithm === 'pbes2') {
      if(typeof options.cipher === 'undefined') options.cipher = 'aes256-cbc';
      if(typeof options.prf === 'undefined') options.prf = 'hmacWithSHA256';
      const kdfAlgorithm = 'pbkdf2'; // TODO: currently only pbkdf2 is available
      const encryptedPBES2 = encryptPBES2(binKey, options.passphrase, kdfAlgorithm, options.prf, options.iterationCount, options.cipher);
      return encodePBES2(encryptedPBES2);
    }
    else {
      const encryptedPBES1 = encryptPBES1(binKey, options.passphrase, options.algorithm, options.iterationCount);
      encryptedPBES1.encryptionAlgorithm.algorithm = params.passwordBasedEncryptionSchemes[encryptedPBES1.encryptionAlgorithm.algorithm].oid;
      encryptedPBES1.encryptionAlgorithm.parameters = PBEParameter.encode(encryptedPBES1.encryptionAlgorithm.parameters, 'der');
      return EncryptedPrivateKeyInfo.encode(encryptedPBES1, 'der');
    }
};
const getAlgorithmFromOid = (oid, oidDict) => {
    return Object.keys(oidDict).filter( (k) => oidDict[k].oid.toString() === oid.toString());
}
const getAlgorithmFromOidStrict = (oid, dict) => {
    const array = getAlgorithmFromOid(oid, dict);
    if (array.length === 0) throw new Error('UnsupportedAlgorithm');
    return array[0];
};
const params = {
  // oid is referred to rfc5480 https://www.ietf.org/rfc/rfc5480.txt
  namedCurves: {
    'P-256': {indutnyName: 'p256', payloadSize: 32, oid: [1, 2, 840, 10045, 3, 1, 7]},
    'P-384': {indutnyName: 'p384', payloadSize: 48, oid: [1, 3, 132, 0, 34]},
    'P-521': {indutnyName: 'p521', payloadSize: 66, oid: [1, 3, 132, 0, 35]},
    'P-256K': {indutnyName: 'secp256k1', payloadSize: 32, oid: [1, 3, 132, 0, 10]},
  },

  // https://tools.ietf.org/html/rfc3279
  publicKeyAlgorithms: {
    'EC': {oid: [1, 2, 840, 10045, 2, 1]},
    'RSA': {oid: [1, 2, 840, 113549, 1, 1, 1]}
  },

  passwordBasedEncryptionSchemes: {
    // PBES1
    'pbeWithMD5AndDES-CBC': {oid: [1, 2, 840, 113549, 1, 5, 3 ], hash: 'MD5', encrypt: 'DES-CBC'},
    'pbeWithSHA1AndDES-CBC': {oid: [1, 2, 840, 113549, 1, 5, 10 ], hash: 'SHA-1', encrypt: 'DES-CBC'},

    // PBES2
    'pbes2': {oid:  [ 1, 2, 840, 113549, 1, 5, 13 ]}
  },

  keyDerivationFunctions: {
    'pbkdf2': {oid: [ 1, 2, 840, 113549, 1, 5, 12 ], defaultSaltLen: 8}
  },

  pbkdf2Prfs: {
    'hmacWithSHA1': {oid: [1, 2, 840, 113549, 2, 7], hash: 'SHA-1'},
    'hmacWithSHA256': {oid: [1, 2, 840, 113549, 2, 9], hash: 'SHA-256'},
    'hmacWithSHA384': {oid: [1, 2, 840, 113549, 2, 10], hash: 'SHA-384'},
    'hmacWithSHA512': {oid: [1, 2, 840, 113549, 2, 11], hash: 'SHA-512'}
  },

  encryptionSchemes: {
    'des-ede3-cbc': {oid: [ 1, 2, 840, 113549, 3, 7 ], keyLength: 24, ivLength: 8},
    'aes128-cbc': {oid: [ 2, 16, 840, 1, 101, 3, 4, 1, 2 ], keyLength: 16, ivLength: 16},
    'aes192-cbc': {oid: [ 2, 16, 840, 1, 101, 3, 4, 1, 22 ], keyLength: 24, ivLength: 16},
    'aes256-cbc': {oid: [ 2, 16, 840, 1, 101, 3, 4, 1, 42 ], keyLength: 32, ivLength: 16}
  },

  hashes: {
    'SHA-256': {hashSize: 32},
    'SHA-384': {hashSize: 48},
    'SHA-512': {hashSize: 64},
    'SHA-1': {hashSize: 20}, // SHOULD NOT USE
    'MD5': {hashSize: 16} // SHOULD NOT USE
  }
};
const encodePBES2 = (decoded) => {
    const epki = { encryptionAlgorithm: {} };
    // algorithm
    epki.encryptionAlgorithm.algorithm = params.passwordBasedEncryptionSchemes[decoded.encryptionAlgorithm.algorithm].oid;
    // kdf
    const kdf = decoded.encryptionAlgorithm.parameters.keyDerivationFunc;
    if(kdf.algorithm === 'pbkdf2') {
      kdf.parameters.prf.algorithm = params.pbkdf2Prfs[kdf.parameters.prf.algorithm].oid;
      kdf.parameters = PBKDF2Params.encode(kdf.parameters, 'der');
    } else throw new Error('Unsupported KDF');
    kdf.algorithm = params.keyDerivationFunctions[kdf.algorithm].oid;
    // encryptionScheme
    const eS = decoded.encryptionAlgorithm.parameters.encryptionScheme;
    if(Object.keys(PBES2ESParams).indexOf(eS.algorithm) >= 0){
      eS.parameters = PBES2ESParams[eS.algorithm].encode(eS.parameters, 'der');
    } else throw new Error('Unsupported Cipher');
    eS.algorithm = params.encryptionSchemes[eS.algorithm].oid;
    // params
    epki.encryptionAlgorithm.parameters = PBES2Params.encode({ keyDerivationFunc: kdf, encryptionScheme: eS }, 'der');
    // encoded data
    epki.encryptedData = decoded.encryptedData;
    return EncryptedPrivateKeyInfo.encode(epki, 'der');
};
const decodePBES2 = (rawParams) => {
    const pbes2Params = PBES2Params.decode(rawParams, 'der');
    // keyDerivationFunc
    const kdfAlgorithm = getAlgorithmFromOidStrict(pbes2Params.keyDerivationFunc.algorithm, params.keyDerivationFunctions);
    let iterationCount;
    let salt;
    let prf;
    if (kdfAlgorithm === 'pbkdf2') {
      const pbkdf2Params = PBKDF2Params.decode(pbes2Params.keyDerivationFunc.parameters, 'der');
      prf = {
        algorithm: getAlgorithmFromOidStrict(pbkdf2Params.prf.algorithm, params.pbkdf2Prfs),
        parameters: pbkdf2Params.prf.parameters
      };
      iterationCount = pbkdf2Params.iterationCount;
      salt = {type: pbkdf2Params.salt.type, value: pbkdf2Params.salt.value};
    } else throw new Error('Unsupported KDF');
    //encryptionScheme
    const encryptionScheme = getAlgorithmFromOidStrict(pbes2Params.encryptionScheme.algorithm, params.encryptionSchemes);
    let encryptionParams;
    if(Object.keys(PBES2ESParams).indexOf(encryptionScheme) >= 0){
      encryptionParams = PBES2ESParams[encryptionScheme].decode(pbes2Params.encryptionScheme.parameters, 'der');
    } else throw new Error('Unsupported Cipher'); // TODO: Other Encryption Scheme
    return {
      keyDerivationFunc: {
        algorithm: kdfAlgorithm,
        parameters: { salt, iterationCount, prf }
      },
      encryptionScheme: {
        algorithm: encryptionScheme,
        parameters: encryptionParams
      }
    };
};
const encryptPBES2 = (binKey, passphrase, kdfAlgorithm, prf, iterationCount, cipher) => {
    // kdf
    const pBuffer = stringToArrayBuffer(passphrase);
    const salt = getRandomBytes(
      params.keyDerivationFunctions[kdfAlgorithm].defaultSaltLen
    ); // TODO: currently only salt length of 8 is available
    const keyLength = params.encryptionSchemes[cipher].keyLength; // get keyLength
    let key;
    if (kdfAlgorithm === 'pbkdf2') {
      key = pbkdf2(pBuffer, salt, iterationCount, keyLength, params.pbkdf2Prfs[prf].hash);
    } else throw new Error('Unsupported KDF');
    // encrypt
    let iv;
    let encryptedData;
    if (cipher === 'des-ede3-cbc') { // TODO other encryption schemes
      iv = Buffer.from(getRandomBytes(params.encryptionSchemes[cipher].ivLength));
      const CBC = des.CBC.instantiate(des.EDE);
      const ct = CBC.create({ type: 'encrypt', key: Buffer.from(key), iv });
      encryptedData = Buffer.from(ct.update(binKey).concat(ct.final()));
    }
    else if (cipher === 'aes128-cbc' || cipher === 'aes192-cbc' || cipher === 'aes256-cbc'){
      iv = getRandomBytes(params.encryptionSchemes[cipher].ivLength);
      encryptedData = Buffer.from( jscaes_encrypt(
        new Uint8Array(binKey), key, {name: 'AES-CBC', iv}
      ));
      iv = Buffer.from(iv);
    } else throw new Error('Unsupported Cipher');
  
    // structure
    return {
      encryptedData,
      encryptionAlgorithm: {
        algorithm: 'pbes2',
        parameters: {
          keyDerivationFunc: {
            algorithm: kdfAlgorithm,
            parameters: {
              salt: {type: 'specified', value: Buffer.from(salt)},
              iterationCount: new BN(iterationCount),
              prf: {algorithm: prf, parameters: Buffer.from([0x05, 0x00])}
            }
          },
          encryptionScheme: { algorithm: cipher, parameters: iv }
        }
      }
    }
};
const getRandomBytes = (len) => {
    const array =new Uint8Array(crypto.randomBytes(len)); 
    return array
};
const pbkdf_hashes = {
    'SHA-256': {hashSize: 32},
    'SHA-384': {hashSize: 48},
    'SHA-512': {hashSize: 64},
    'SHA-1': {hashSize: 20}, // SHOULD NOT USE
    'MD5': {hashSize: 16} // SHOULD NOT USE
}
const pbkdf1 = (p, s, c, dkLen, hash) => {
    assertPbkdf(p, s, c, dkLen, hash);
    if(typeof p === 'string') p = stringToArrayBuffer(p);
    if(dkLen > pbkdf_hashes[hash].hashSize) throw new Error('Derived Key TooLong');
    let seed = new Uint8Array(p.length + s.length);
    seed.set(p);
    seed.set(s, p.length);
    for(let i = 0; i < c; i++){
      seed = jschash_compute(seed, hash);
    }
    return seed.slice(0, dkLen);
};
const pbkdf2 = (p, s, c, dkLen, hash) => {
    assertPbkdf(p, s, c, dkLen, hash);
    if(typeof p === 'string') p = stringToArrayBuffer(p);
    const hLen = pbkdf_hashes[hash].hashSize;
    if(dkLen > (Math.pow(2, 32) - 1) * hLen) throw new Error('Derived Key TooLong');
    const l = Math.ceil(dkLen/hLen);
    const r = dkLen - (l-1)*hLen;

    const funcF = (i) => {
      const seed = new Uint8Array(s.length + 4);
      seed.set(s);
      seed.set(nwbo(i+1, 4), s.length);
      let u = jschmac_compute(p, seed, hash);
      let outputF = new Uint8Array(u);
      for(let j = 1; j < c; j++){
        u = jschmac_compute(p, u, hash);
        outputF = u.map( (elem, idx) => elem ^ outputF[idx]);
      }
      return {index: i, value: outputF};
    };
    const DK = new Uint8Array(dkLen);
    const Tis = [];
    for(let i = 0; i < l; i++) Tis.push(funcF(i));
    Tis.forEach( (elem) => {
      if (elem.index !== l - 1) DK.set(elem.value, elem.index*hLen);
      else DK.set(elem.value.slice(0, r), elem.index*hLen);
    });
    return DK;
}
const assertPbkdf = (p, s, c, dkLen, hash) => {
    if (typeof p !== 'string' && !(p instanceof Uint8Array)) throw new Error('Password Is Not Uint8Array Nor String');
    if (!(s instanceof Uint8Array)) throw new Error('Salt Must Be Uint8Array');
    if (typeof c !== 'number' || c <= 0) throw new Error('Invalid Iteration Count');
    if (typeof dkLen !== 'number' || dkLen <= 0) throw new Error('Invalid Derived Key Length');
    if (Object.keys(pbkdf_hashes).indexOf(hash) < 0) throw new Error('UnsupportedH ash Algorithm');
    return true;
};
const nwbo = (num, len) => {
    const arr = new Uint8Array(len);
    for(let i=0; i<len; i++) arr[i] = 0xFF && (num >> ((len - i - 1)*8));
    return arr;
};
const jschmac_hashes = {
    'SHA-256': {nodeName: 'sha256', hashSize: 32, blockSize: 64},
    'SHA-384': {nodeName: 'sha384', hashSize: 48, blockSize: 128},
    'SHA-512': {nodeName: 'sha512', hashSize: 64, blockSize: 128},
    'SHA-1': {nodeName: 'sha1', hashSize: 20, blockSize: 64},
    'MD5': {nodeName: 'md5', hashSize: 16, blockSize: 64}
}
const jschmac_compute = (key, data, hash = 'SHA-256') => {
    const f = crypto.createHmac(jschmac_hashes[hash].nodeName, key);
    return new Uint8Array(f.update(data).digest());
};
const jscaes_ciphers = {
    'AES-GCM': {
    nodePrefix: 'aes',
    nodeSuffix: 'gcm',
    ivLength: 12,  // default value of iv length, 12 bytes is recommended for AES-GCM
    tagLength: 16,
    staticIvLength: true // if true, IV length must be always ivLength.
    },
    'AES-CBC': {
    nodePrefix: 'aes',
    nodeSuffix: 'cbc',
    ivLength: 16,
    staticIvLength: true
    }
}
const jscaes_encrypt = (msg, key, {name = 'AES-GCM', iv, additionalData=new Uint8Array([]), tagLength}) => {
    // assertion and sanitizing
    if(!(msg instanceof Uint8Array) || !(key instanceof Uint8Array)) throw new Error('Invalid Arguments');
    assertAlgorithms({name, iv, tagLength});
    if(jscaes_ciphers[name].tagLength && !tagLength) tagLength = jscaes_ciphers[name].tagLength;
    let data;
    try{
    data = nodeapi_encrypt(msg, key, {name, iv, additionalData, tagLength});
    } catch(e) {throw e}
    return data;
};
const jscaes_decrypt = (data, key, {name='AES-GCM', iv, additionalData=new Uint8Array([]), tagLength}) => {
    // assertion and sanitizing
    if(!(data instanceof Uint8Array) || !(key instanceof Uint8Array)) throw new Error('Invalid Arguments');
    assertAlgorithms({name, iv, tagLength});
    if(jscaes_ciphers[name].tagLength && !tagLength) tagLength = jscaes_ciphers[name].tagLength;
    let msg;
    try{
    msg = nodeapi_decrypt(data, key, {name, iv, additionalData, tagLength});
    } catch(e) {throw e}
    return msg;
};
const assertAlgorithms = ({name, iv, tagLength}) => {
    if(Object.keys(jscaes_ciphers).indexOf(name) < 0) throw new Error('Unsupported Algorithm');
    if(jscaes_ciphers[name].ivLength){
      if(!(iv instanceof Uint8Array)) throw new Error('Invalid Arguments');
      if(iv.byteLength < 2 || iv.byteLength > 16) throw new Error('Invalid IV Length');
      if(jscaes_ciphers[name].staticIvLength && (jscaes_ciphers[name].ivLength !== iv.byteLength)) throw new Error('Invalid IV Length');
    }
    if(jscaes_ciphers[name].tagLength && tagLength){
      if(!Number.isInteger(tagLength)) throw new Error('Invalid Arguments');
      if(tagLength < 4 || tagLength > 16) throw new Error('Invalid Tag Length');
    }
};
const nodeapi_ciphers = {
    'AES-GCM': {
      nodePrefix: 'aes',
      nodeSuffix: 'gcm',
      ivLength: 12,  // default value of iv length, 12 bytes is recommended for AES-GCM
      tagLength: 16,
      staticIvLength: true // if true, IV length must be always ivLength.
    },
    'AES-CBC': {
      nodePrefix: 'aes',
      nodeSuffix: 'cbc',
      ivLength: 16,
      staticIvLength: true
    }
}
const nodeapi_decrypt = (data, key, {name, iv, additionalData, tagLength}) => {
    let alg = nodeapi_ciphers[name].nodePrefix;
    alg = `${alg}-${(key.byteLength*8).toString()}-`;
    alg = alg + nodeapi_ciphers[name].nodeSuffix;
    let decipher;
    let body;
    switch(name){
    case 'AES-GCM': {
      decipher = crypto.createDecipheriv(alg, key, iv, {authTagLength: tagLength});
      decipher.setAAD(additionalData);
      body = data.slice(0, data.length - tagLength);
      const tag = data.slice(data.length - tagLength);
      decipher.setAuthTag(tag);
      break;
    }
    case 'AES-CBC': {
      decipher = crypto.createDecipheriv(alg, key, iv);
      body = data;
      break;
    }
    default: throw new Error('Unsupported Cipher');
    }
    const decryptedBody = decipher.update(body);
    let final;
    try{
      final = decipher.final();
    } catch (e) {
      throw new Error('Decryption Failure');
    }
    const msg = new Uint8Array(final.length + decryptedBody.length);
    msg.set(decryptedBody);
    msg.set(final, decryptedBody.length);
    return msg;
};
const nodeapi_encrypt = (msg, key, {name, iv, additionalData, tagLength}) => {
    let alg = nodeapi_ciphers[name].nodePrefix;
    alg = `${alg}-${(key.byteLength*8).toString()}-`;
    alg = alg + nodeapi_ciphers[name].nodeSuffix;
    let cipher;
    switch(name){
    case 'AES-GCM': {
      cipher = crypto.createCipheriv(alg, key, iv, {authTagLength: tagLength});
      cipher.setAAD(additionalData);
      break;
    }
    case 'AES-CBC': {
      cipher = crypto.createCipheriv(alg, key, iv);
      break;
    }}
    const body = new Uint8Array(cipher.update(msg));
    const final = new Uint8Array(cipher.final());
    let tag = new Uint8Array([]);
    if(name === 'AES-GCM') tag = new Uint8Array(cipher.getAuthTag());
    const data = new Uint8Array(body.length + final.length + tag.length);
    data.set(body);
    data.set(final, body.length);
    data.set(tag, body.length + final.length);
    return data;
};
  
const jschash_hashes = {
    'SHA-256': {nodeName: 'sha256', hashSize: 32},
    'SHA-384': {nodeName: 'sha384', hashSize: 48},
    'SHA-512': {nodeName: 'sha512', hashSize: 64},
    'SHA-1': {nodeName: 'sha1', hashSize: 20}, // SHOULD NOT USE
    'MD5': {nodeName: 'md5', hashSize: 16} // SHOULD NOT USE
  }
const jschash_compute = (msg, hash = 'SHA-256') => {
    if(Object.keys(jschash_hashes).indexOf(hash) < 0) throw new Error('Unsupported Hash Algorithm');
    if(!(msg instanceof Uint8Array)) throw new Error('Unsupported Message Type');
    let msgHash;
    msgHash = nodedigest(hash, msg);
    return new Uint8Array(msgHash);
}
const nodedigest = (hash, msg) => {
    const alg = jschash_hashes[hash].nodeName;
    const hashFunc = crypto.createHash(alg);
    hashFunc.update(msg);
    return hashFunc.digest();
};
const getJwkThumbprint = (jwkey, alg='SHA-256', output='binary') => {
    // assertion
    if(['hex', 'binary','base64'].indexOf(output) < 0) throw new Error('Unsupported Output Format');
    let jsonString;
    if(jwkey.kty === 'EC'){
      jsonString = JSON.stringify({crv: jwkey.crv, kty: jwkey.kty, x: jwkey.x, y: jwkey.y});
    }
    else if (jwkey.kty === 'RSA'){
      jsonString = JSON.stringify({e: jwkey.e, kty: jwkey.kty, n: jwkey.n});
    }
    else throw new Error('Unsupported Key Type');
    const uint8json = new Uint8Array(Buffer.from(jsonString, 'utf8'));
    const thumbPrintBuf = jschash_compute(uint8json, alg);
    if(output === 'hex') return arrayBufferToHexString(thumbPrintBuf);
    else if(output === 'base64') return encodeBase64(thumbPrintBuf);
    else if (output === 'binary') return thumbPrintBuf;
};

module.exports = Key;
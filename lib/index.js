const asn = require('asn1.js');
const BN = asn.bignum;
const des = require('des.js');
const crypto = require('crypto');
const Ec = require('elliptic').ec;
const cloneDeep = require('lodash.clonedeep');

// This will only work with higher versions of nodejs >=10 use keypair instead
const getKeyPair = (type = "ec", options = {modulusLength: 4096, namedCurve: 'secp256k1', publicKeyEncoding: {type: 'spki', format: 'pem'}, privateKeyEncoding: {type: 'pkcs8', format: 'pem'}}) => {
  return {publicKey, privateKey} = crypto.generateKeyPairSync(type, options)
}

// https://github.com/junkurihara/jscu/tree/develop/packages/js-crypto-key-utils
class Key {
    constructor(format, key){
        const localKey = cloneDeep(key);
        this._jwk = {};
        this._der = null;
        this._current = { jwk: false, der: false};
        if(format === 'jwk'){
            this._setJwk(localKey);
          }
        else if (format === 'der' || format === 'pem'){
            if(format === 'der' && !(localKey instanceof Uint8Array)) throw new Error('DerKeyMustBeUint8Array');
            if(format === 'pem' && (typeof localKey !== 'string')) throw new Error('PemKeyMustBeString');
            this._setAsn1(localKey, format);
        } else throw new Error('UnsupportedType');
    }
    _setJwk(jwkey){
        this._type = getJwkType(jwkey); // this also check key format
        this._jwk = jwkey;
        if(this._isEncrypted) this._der = null;
        this._isEncrypted = false;
        this._setCurrentStatus();
    }
    _setAsn1(asn1key, format){
        this._type = (isAsn1Public(asn1key, format)) ? 'public' : 'private'; // this also check key format
        this._isEncrypted = isAsn1Encrypted(asn1key, format);
        this._der = (format === 'pem') ? pemToBin(asn1key): asn1key;
        this._setCurrentStatus();
    }
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
    export(format = 'jwk', options={}){
        // global assertion
        if(['pem', 'der', 'jwk'].indexOf(format) < 0) throw new Error('UnsupportedFormat');
        // return 'as is' without passphrase when nothing is given as 'options'
        // only for the case to export der key from der key (considering encrypted key). expect to be called from getter
        if(this._isEncrypted && this._type === 'private'){
          if((format === 'der' || format === 'pem') && Object.keys(options).length === 0 && this._current.der) {
            return (format === 'pem') ? binToPem(this._der, 'encryptedPrivate') : this._der;
          }
          else throw new Error('DecryptionRequired');
        }
        // first converted to jwk
        let jwkey;
        if(this._current.jwk){
          jwkey = this._jwk;
        }
        else if(this._current.der) {
          jwkey = toJwkFrom('der', this._der);
        }
        else throw new Error('InvalidStatus');
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
        }
        else return jwkey;
    }
    encrypt (passphrase){
        if(this._isEncrypted) throw new Error('AlreadyEncrypted');
        const options = {encryptParams: {passphrase}};
        this._setAsn1(this.export('der', options), 'der');
        return true;
    }
    decrypt (passphrase){
        if(!this._isEncrypted) throw new Error('NotEncrypted');
        let jwkey;
        if(this._current.der && typeof passphrase === 'string'){
          jwkey = toJwkFrom('der', this._der, {passphrase}); // type is not specified here to import jwk
        }
        else throw new Error('FailedToDecrypt');
        this._setJwk(jwkey);
        return true;
    }
    getJwkThumbprint(alg='SHA-256', output='binary'){
        if(this._isEncrypted) throw new Error('DecryptionRequired');
        return getJwkThumbprint(this.export('jwk'), alg, output);
    }
    get keyType(){
        if(this._isEncrypted) throw new Error('DecryptionRequired');
        const jwkey = this.export('jwk');
        return jwkey.kty
    }
    get jwkThumbprint(){
        return this.getJwkThumbprint();
    }
    get isEncrypted(){ return this._isEncrypted; }
    get isPrivate(){ return this._type === 'private'; }
    get der(){ return this.export('der'); }
    get pem(){ return this.export('pem'); }
    get jwk(){ return this.export('jwk'); }
}
const getJwkType = (jwkey) => {
    if(jwkey.kty === 'EC'){
      if (jwkey.x && jwkey.y && jwkey.d) return 'private';
      else if (jwkey.x && jwkey.y) return 'public';
      else throw new Error('InvalidECKey');
    }
    else if (jwkey.kty === 'RSA'){
      if (jwkey.n && jwkey.e && jwkey.d && jwkey.p && jwkey.q && jwkey.dp && jwkey.dq && jwkey.qi) return 'private';
      else if (jwkey.n && jwkey.e) return 'public';
      else throw new Error('InvalidRSAKey');
    }
    else throw new Error('UnsupportedJWKType');
};
const isAsn1Public = (key, format='pem') => {
    let keyType;
    try{ keyType = getAsn1KeyType(key, format);} catch(e) {return false;}
    return (keyType === 'public');
};
const isAsn1Encrypted = (key, format='pem') => {
    let keyType;
    try{ keyType = getAsn1KeyType(key, format);} catch(e) {return false;}
    return keyType === 'encryptedPrivate';
};
const getAsn1KeyType = (key, format='pem') => {
    // Peel the pem strings
    const binKey = (format === 'pem') ? pemToBin(key, 'private') : key;
  
    const decoded = KeyStructure.decode(Buffer.from(binKey), 'der');
    if (decoded.type === 'encryptedPrivateKeyInfo') return 'encryptedPrivate';
    else if (decoded.type === 'oneAsymmetricKey') return 'private';
    else if (decoded.type === 'subjectPublicKeyInfo') return 'public';
    else throw new Error('NotSpkiNorPkcs8Key');
};
const getSec1KeyType = (sec1key, namedCurve)=> {
    let format;
    if (sec1key instanceof Uint8Array) format = 'binary';
    else if (typeof sec1key === 'string') format = 'string';
    else throw new Error('InvalidObjectType');
    const binKey = (format === 'string') ? hexStringToArrayBuffer(sec1key): sec1key;
    const len = params.namedCurves[namedCurve].payloadSize;
    // original key type
    if (binKey.length <= len) return 'private';
    else if (
      (binKey.length === 2*len+1 && binKey[0] === 0x04)
      || (binKey.length === len+1 && (binKey[0] === 0x02 || binKey[0] === 0x03))
    ) return 'public';
    else throw new Error('UnsupportedKeyStructure');
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
    if(typeof Buffer === 'undefined') throw new Error('UnsupportedEnvironment');
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
    if(typeof Buffer === 'undefined') throw new Error('UnsupportedEnvironment');
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

sanitizeTypedArrayAndArrayBuffer = (data) => {
    if(data instanceof Uint8Array) return data;
    if (ArrayBuffer.isView(data) && typeof data.buffer !== 'undefined') { // TypedArray except Uint8Array
      return new Uint8Array(data.buffer);
    }
    else if (data instanceof ArrayBuffer) { // ArrayBuffer
      return new Uint8Array(data);
    }
    else throw new Error('Input must be an ArrayBuffer or a TypedArray');
};
getAsciiIfAscii = (data) => {
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
    if(!(array instanceof Uint8Array)) throw new Error('NonUint8Array');
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
    if(!(array instanceof Uint8Array)) throw new Error('NonUint8Array');
    if(array.length > len) throw new Error('InvalidLength');
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
      this.key('parameters').explicit(0).optional().any(), // rfc suggested that this must be implemented
      this.key('publicKey').explicit(1).optional().bitstr() // rfc suggested that this must be implemented
    );
});
const ECPrivateKeyAlt = asn.define('ECPrivateKey', function() {
    this.seq().obj(
      this.key('version').int(),
      this.key('privateKey').octstr(),
      // this.key('parameters').explicit(0).optional().any(), // rfc suggested that this must be implemented
      this.key('publicKey').explicit(1).optional().bitstr() // rfc suggested that this must be implemented
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
    if (['pem', 'der'].indexOf(input) < 0) throw new Error('InvalidInputForm');
    if (typeof options.outputPublic !== 'undefined' && typeof options.outputPublic !== 'boolean') throw new Error('outputPublicMustBeBoolean');
    // default values
    if ((input === 'der' || input === 'pem') && typeof options.passphrase === 'undefined') options.passphrase = '';
    // In the case of PEM
    if (input === 'der' || input === 'pem') {
      return asn1enc_toJwk(key, input, {outputPublic: options.outputPublic, passphrase: options.passphrase});
    }
    else throw new Error('UnsupportedConversion');
};
const asn1enc_toJwk = (key, format, {outputPublic, passphrase}) => {
    // Peel the pem strings
    const binKey = (format === 'pem') ? pemToBin(key) : key;
    // decode binary spki/pkcs8-formatted key to parsed object
    let decoded;
    try { decoded = KeyStructure.decode(Buffer.from(binKey), 'der'); }
    catch (e) { throw e }
    let type;
    if(decoded.type === 'subjectPublicKeyInfo'){
      type = 'public';
      decoded = decoded.value;
    }
    else {
      type = (typeof outputPublic === 'boolean' && outputPublic) ? 'public' : 'private';
      if(decoded.type === 'encryptedPrivateKeyInfo') decoded = decryptEncryptedPrivateKeyInfo(decoded.value, passphrase);
      else if (decoded.type === 'oneAsymmetricKey') decoded = decoded.value;
      else throw new Error('UnsupportedKeyStructure');
    }
    const keyTypes = getAlgorithmFromOid(
      (type === 'public') ? decoded.algorithm.algorithm : decoded.privateKeyAlgorithm.algorithm,
      params.publicKeyAlgorithms
    );
    if(keyTypes.length < 1) throw new Error('UnsupportedKey');
    if (keyTypes[0] === 'EC') {
      return asn1ec_toJWK(decoded, type);
    }
    else if (keyTypes[0] === 'RSA'){
      return asn1rsa_toJwk(decoded, type);
    }
    else throw new Error('InvalidKeyType');
};
const asn1rsa_toJwk = (decoded, type) => {
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
      return {
        kty: 'RSA',
        n: encodeBase64Url(pruneLeadingZeros(privateKeyElems.modulus)),
        e: encodeBase64Url(pruneLeadingZeros(privateKeyElems.publicExponent)),
        d: encodeBase64Url(pruneLeadingZeros(privateKeyElems.privateExponent)),
        p: encodeBase64Url(pruneLeadingZeros(privateKeyElems.prime1)),
        q: encodeBase64Url(pruneLeadingZeros(privateKeyElems.prime2)),
        dp: encodeBase64Url(pruneLeadingZeros(privateKeyElems.exponent1)),
        dq: encodeBase64Url(pruneLeadingZeros(privateKeyElems.exponent2)),
        qi: encodeBase64Url(pruneLeadingZeros(privateKeyElems.coefficient))
      };
    }
}
const asn1ec_toJWK = (decoded, type) => {
    if (type === 'public'){ // SPKI
      decoded.algorithm.parameters = ECParameters.decode(decoded.algorithm.parameters, 'der'); // overwrite nested binary object as parsed object
      const octPubKey = new Uint8Array(decoded.subjectPublicKey.data); // convert oct key to jwk
      const namedCurves = getAlgorithmFromOid(decoded.algorithm.parameters.value, params.namedCurves);
      if(namedCurves.length < 1) throw new Error('UnsupportedCurve');
      return octKeyToJwk(octPubKey, namedCurves[0], {outputPublic: true});
    }
    else if (type === 'private'){ // PKCS8
      decoded.privateKeyAlgorithm.parameters = ECParameters.decode(decoded.privateKeyAlgorithm.parameters, 'der');
      // Work around for optional private key parameter field.
      try{ decoded.privateKey = ECPrivateKey.decode(decoded.privateKey, 'der'); }
      catch(e){ decoded.privateKey = ECPrivateKeyAlt.decode(decoded.privateKey, 'der'); }
      const octPrivKey = new Uint8Array(decoded.privateKey.privateKey);
      const namedCurves = getAlgorithmFromOid(decoded.privateKeyAlgorithm.parameters.value, params.namedCurves);
      if(namedCurves.length < 1) throw new Error('UnsupportedCurve');
      return octKeyToJwk(octPrivKey, namedCurves[0], {outputPublic: false});
    }
};
const octKeyToJwk = (octkey, namedCurve, {outputPublic}) => {
    if (Object.keys(params.namedCurves).indexOf(namedCurve) < 0) throw new Error('UnsupportedCurve');
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
    if (['pem', 'der'].indexOf(output) < 0) throw new Error('InvalidOutputForm');
    if (typeof jwkey !== 'object') throw new Error('InvalidJWKAsObject');
    if (jwkey.kty !== 'EC' && jwkey.kty !== 'RSA') throw new Error('UnsupportedKeyType');
    if (typeof options.outputPublic !== 'undefined' && typeof options.outputPublic !== 'boolean') throw new Error('outputPublicMustBeBoolean');
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
    else throw new Error('UnsupportedConversion');
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
    if (Object.keys(params.namedCurves).indexOf(jwk.crv) < 0) throw new Error('UnsupportedCurve');
    const octetPublicKey = octKeyFromJwk(jwk, {outputFormat: 'binary', outputPublic: true, compact});
    const publicKeyAlgorithmOid = params.publicKeyAlgorithms['EC'].oid;
    const publicKey = {unused: 0, data: Array.from(octetPublicKey)};//Buffer.from(octkeyObj.publicKey)};
    const parameters = ECParameters.encode({ type: 'namedCurve', value: params.namedCurves[jwk.crv].oid }, 'der');
    const algorithm = { algorithm: publicKeyAlgorithmOid, parameters };
    const decoded = {};
    if(type === 'public'){ // SPKI
      decoded.subjectPublicKey = publicKey;
      decoded.algorithm = algorithm;
    }
    else if (type === 'private') { // PKCS8
      const octetPrivateKey = octKeyFromJwk(jwk, {outputFormat: 'binary', outputPublic: false, compact});
      decoded.version = 0; // no public key presents for v2 (0)
      decoded.privateKeyAlgorithm = algorithm;
      decoded.privateKey = ECPrivateKey.encode({
        version: 1,
        privateKey: Array.from(octetPrivateKey), //Buffer.from(octkeyObj.privateKey),
        parameters,
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
    else throw new Error('UnsupportedEncryptionAlgorithm');
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
    else throw new Error('UnsupportedEncryptionAlgorithm');
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
      if (kdf.parameters.salt.type !== 'specified') throw new Error('UnsupportedSaltSource');
      const salt = new Uint8Array(kdf.parameters.salt.value);
      const iterationCount = kdf.parameters.iterationCount.toNumber();
      const prf = kdf.parameters.prf.algorithm;
      key = pbkdf2(pBuffer, salt, iterationCount, keyLength, params.pbkdf2Prfs[prf].hash);
    }
    else throw new Error('UnsupportedKDF');
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
    } else throw new Error('UnsupportedEncryptionAlgorithm');
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
    } else throw new Error('UnsupportedKDF');
    kdf.algorithm = params.keyDerivationFunctions[kdf.algorithm].oid;
    // encryptionScheme
    const eS = decoded.encryptionAlgorithm.parameters.encryptionScheme;
    if(Object.keys(PBES2ESParams).indexOf(eS.algorithm) >= 0){
      eS.parameters = PBES2ESParams[eS.algorithm].encode(eS.parameters, 'der');
    } else throw new Error('UnsupportedCipher');
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
    } else throw new Error('UnsupportedKDF');
    //encryptionScheme
    const encryptionScheme = getAlgorithmFromOidStrict(pbes2Params.encryptionScheme.algorithm, params.encryptionSchemes);
    let encryptionParams;
    if(Object.keys(PBES2ESParams).indexOf(encryptionScheme) >= 0){
      encryptionParams = PBES2ESParams[encryptionScheme].decode(pbes2Params.encryptionScheme.parameters, 'der');
    } else throw new Error('UnsupportedCipher'); // TODO: Other Encryption Scheme
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
    } else throw new Error('UnsupportedKDF');
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
    } else throw new Error('UnsupportedCipher');
  
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
    if(dkLen > pbkdf_hashes[hash].hashSize) throw new Error('DerivedKeyTooLong');
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
    if(dkLen > (Math.pow(2, 32) - 1) * hLen) throw new Error('DerivedKeyTooLong');
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
    if (typeof p !== 'string' && !(p instanceof Uint8Array)) throw new Error('PasswordIsNotUint8ArrayNorString');
    if (!(s instanceof Uint8Array)) throw new Error('SaltMustBeUint8Array');
    if (typeof c !== 'number' || c <= 0) throw new Error('InvalidIterationCount');
    if (typeof dkLen !== 'number' || dkLen <= 0) throw new Error('InvalidDerivedKeyLength');
    if (Object.keys(pbkdf_hashes).indexOf(hash) < 0) throw new Error('UnsupportedHashAlgorithm');
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
    if(!(msg instanceof Uint8Array) || !(key instanceof Uint8Array)) throw new Error('InvalidArguments');
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
    if(!(data instanceof Uint8Array) || !(key instanceof Uint8Array)) throw new Error('InvalidArguments');
    assertAlgorithms({name, iv, tagLength});
    if(jscaes_ciphers[name].tagLength && !tagLength) tagLength = jscaes_ciphers[name].tagLength;
    let msg;
    try{
    msg = nodeapi_decrypt(data, key, {name, iv, additionalData, tagLength});
    } catch(e) {throw e}
    return msg;
};
const assertAlgorithms = ({name, iv, tagLength}) => {
    if(Object.keys(jscaes_ciphers).indexOf(name) < 0) throw new Error('UnsupportedAlgorithm');
    if(jscaes_ciphers[name].ivLength){
      if(!(iv instanceof Uint8Array)) throw new Error('InvalidArguments');
      if(iv.byteLength < 2 || iv.byteLength > 16) throw new Error('InvalidIVLength');
      if(jscaes_ciphers[name].staticIvLength && (jscaes_ciphers[name].ivLength !== iv.byteLength)) throw new Error('InvalidIVLength');
    }
    if(jscaes_ciphers[name].tagLength && tagLength){
      if(!Number.isInteger(tagLength)) throw new Error('InvalidArguments');
      if(tagLength < 4 || tagLength > 16) throw new Error('InvalidTagLength');
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
    default: throw new Error('UnsupportedCipher');
    }
    const decryptedBody = decipher.update(body);
    let final;
    try{
      final = decipher.final();
    } catch (e) {
      throw new Error('DecryptionFailure');
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
    if(Object.keys(jschash_hashes).indexOf(hash) < 0) throw new Error('UnsupportedHashAlgorithm');
    if(!(msg instanceof Uint8Array)) throw new Error('UnsupportedMessageType');
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
    if(['hex', 'binary','base64'].indexOf(output) < 0) throw new Error('UnsupportedOutputFormat');
    let jsonString;
    if(jwkey.kty === 'EC'){
      jsonString = JSON.stringify({crv: jwkey.crv, kty: jwkey.kty, x: jwkey.x, y: jwkey.y});
    }
    else if (jwkey.kty === 'RSA'){
      jsonString = JSON.stringify({e: jwkey.e, kty: jwkey.kty, n: jwkey.n});
    }
    else throw new Error('UnsupportedKeyType');
    const uint8json = new Uint8Array(Buffer.from(jsonString, 'utf8'));
    const thumbPrintBuf = jschash_compute(uint8json, alg);
    if(output === 'hex') return arrayBufferToHexString(thumbPrintBuf);
    else if(output === 'base64') return encodeBase64(thumbPrintBuf);
    else if (output === 'binary') return thumbPrintBuf;
};

module.exports = Key;
module.exports.getKeyPair = getKeyPair;
<a name="module_crypto-keys"></a>

## crypto-keys
Node.js javascript tool to generate ,encrypt and decrypt RSA and EC keys formated as PEM / DER.

**Requires**: <code>module:NPM:asn1.js</code>, <code>module:NPM:des.js</code>, <code>module:NPM:elliptic</code>, <code>module:NPM:lodash.clonedeep</code>, <code>module:./jsbn.js:jsbn</code>  
**Author**: Ademar Arvati  
**License**: MIT  
**Example**  
```js
const cryptoKeys = require('crypto-keys')
```

* [crypto-keys](#module_crypto-keys)
    * [Key](#exp_module_crypto-keys--Key) ⏏
        * [new Key(format, key)](#new_module_crypto-keys--Key_new)

<a name="exp_module_crypto-keys--Key"></a>

### Key ⏏
**Kind**: Exported class  
<a name="new_module_crypto-keys--Key_new"></a>

#### new Key(format, key)
Import or Create a Key.


| Param | Type | Default | Description |
| --- | --- | --- | --- |
| format | <code>string</code> |  | Format of key to import ('der', 'pem' or 'jwk') or 'create' to create a new private key |
| key | <code>string</code> \| <code>Uint8Array</code> \| <code>jwk</code> \| <code>Object</code> |  | String for pem key, Uint8Array for der key, {jwk} for jwk key or to create new key. |
| [key.type] | <code>string</code> | <code>&quot;ec&quot;</code> | 'rsa' or 'ec' for key type to be created |
| [key.namedCurve] | <code>string</code> | <code>&quot;P-256K&quot;</code> | Curve for EC type key creation 'P-256', 'P-384', 'P-521', 'P-256K' |
| [key.modulusLength] | <code>integer</code> | <code>2048</code> | Modulus Length for RSA type key creation |
| [key.publicExponent] | <code>integer</code> | <code>65537</code> | Public Exponent for RSA type key creation |

**Example**  
Creating a new private key
```js
privateKey = new cryptoKeys('create', {type:'rsa', modulusLength:2048, publicExponent:65537});
```
Importing a pem public key (string)
```js
key = new cryptoKeys('pem', publicKey);
```

{ title: [32m'Unit Tests Results'[39m,
  filename: [1mnull[22m,
  path: [32m'./'[39m,
  quiet: [33mfalse[39m,
  level: [33m0[39m }
 Unit Tests Results
   - [Node Module for Cryptographic Key Utilities in JavaScript](#node-module-for-cryptographic-key-utilities-in-javascript)
     - [PEM RSA key Pair](#node-module-for-cryptographic-key-utilities-in-javascript-pem-rsa-key-pair)
     - [PEM EC key Pair](#node-module-for-cryptographic-key-utilities-in-javascript-pem-ec-key-pair)

<a name=""></a>
 
<a name="node-module-for-cryptographic-key-utilities-in-javascript"></a>
# Node Module for Cryptographic Key Utilities in JavaScript
Default Key Pair generation using crypto [32m  ✓[0m.
[90m2ms[0m.

```js
// This will only work with higher versions of nodejs >=10
const {publicKey, privateKey} = getKeyPair()
assert.isString(publicKey,'public key is not a string');
assert.isString(privateKey,'public key is not a string');
```

<a name="node-module-for-cryptographic-key-utilities-in-javascript-pem-rsa-key-pair"></a>
## PEM RSA key Pair
Generating key pair ... [32m  ✓[0m.
[31m4.509s[0m.

```js
this._privateKey = new keyutil('create', {type:'rsa', modulusLength:2048, publicExponent:65537});
this._publicKey = new keyutil('jwk', this._privateKey.export('jwk', {outputPublic: true}) )
this._privateKey.encrypt('top secret')
assert.isObject(this._publicKey,'public key is not a object');
assert.isObject(this._privateKey,'public key is not a object');
```

isPrivate of publicKey is False [32m  ✓[0m.
[90m0ms[0m.

```js
assert.isFalse(this._publicKey.isPrivate);
```

isEncrypted of publicKey is False [32m  ✓[0m.
[90m0ms[0m.

```js
assert.isFalse(this._publicKey.isEncrypted);
```

Key type of publicKey is RSA [32m  ✓[0m.
[90m0ms[0m.

```js
assert.equal(this._publicKey.keyType, 'RSA');
```

isPrivate of privateKey is True [32m  ✓[0m.
[90m0ms[0m.

```js
assert.isTrue(this._privateKey.isPrivate);
```

isEncrypted of privateKey is True [32m  ✓[0m.
[90m0ms[0m.

```js
assert.isTrue(this._privateKey.isEncrypted);
```

Decrypt privateKey with wrong password [32m  ✓[0m.
[90m26ms[0m.

```js
assert.throws(()=>this._privateKey.decrypt('just secret'),Error,'DecryptionFailure')
```

Decrypt privateKey with password [32m  ✓[0m.
[90m23ms[0m.

```js
assert.isTrue(this._privateKey.decrypt('top secret'));
```

Key type of privateKey is RSA [32m  ✓[0m.
[90m0ms[0m.

```js
assert.equal(this._privateKey.keyType, 'RSA');
```

Export privateKey as publicKey [32m  ✓[0m.
[33m47ms[0m.

```js
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
```

Encrypt privateKey with password [32m  ✓[0m.
[90m19ms[0m.

```js
assert.isTrue(this._privateKey.encrypt('top secret'));
```

Sign String with encrypted private key and verify with public key [32m  ✓[0m.
[90m5ms[0m.

```js
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
```

<a name="node-module-for-cryptographic-key-utilities-in-javascript-pem-ec-key-pair"></a>
## PEM EC key Pair
Generating key pair ... [32m  ✓[0m.
[31m107ms[0m.

```js
this._privateKey = new keyutil('create', {type:'ec', namedCurve:'P-256K'});
this._publicKey = new keyutil('jwk', this._privateKey.export('jwk', {outputPublic: true}) )
this._privateKey.encrypt('top secret')
assert.isObject(this._publicKey,'public key is not a object');
assert.isObject(this._privateKey,'public key is not a object');
```

isPrivate of publicKey is False [32m  ✓[0m.
[90m0ms[0m.

```js
assert.isFalse(this._publicKey.isPrivate);
```

isEncrypted of publicKey is False [32m  ✓[0m.
[90m0ms[0m.

```js
assert.isFalse(this._publicKey.isEncrypted);
```

Key type of publicKey is EC [32m  ✓[0m.
[90m0ms[0m.

```js
assert.equal(this._publicKey.keyType, 'EC');
```

isPrivate of privateKey is True [32m  ✓[0m.
[90m0ms[0m.

```js
assert.isTrue(this._privateKey.isPrivate);
```

isEncrypted of privateKey is True [32m  ✓[0m.
[90m0ms[0m.

```js
assert.isTrue(this._privateKey.isEncrypted);
```

Decrypt privateKey with wrong password [32m  ✓[0m.
[90m14ms[0m.

```js
assert.throws(()=>{this._privateKey.decrypt('just secret')},Error,'DecryptionFailure')
```

Decrypt privateKey with password [32m  ✓[0m.
[90m20ms[0m.

```js
assert.isTrue(this._privateKey.decrypt('top secret'));
```

Key type of privateKey is EC [32m  ✓[0m.
[90m0ms[0m.

```js
assert.equal(this._privateKey.keyType, 'EC');
```

Export privateKey as publicKey [32m  ✓[0m.
[90m33ms[0m.

```js
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
```

Encrypt privateKey with password [32m  ✓[0m.
[90m14ms[0m.

```js
assert.isTrue(this._privateKey.encrypt('new secret'));
```

Export privateKey with password [32m  ✓[0m.
[90m3ms[0m.

```js
privateKey = new keyutil('der', this._privateKey.der); 
originalPrivateKey = new keyutil('pem', this._privateKey.pem); 
assert.deepEqual(privateKey.der,originalPrivateKey.der);
assert.throws(()=>{this._privateKey.jwk},Error,'DecryptionRequired')
```

Sign String with encrypted private key and verify with public key [32m  ✓[0m.
[90m4ms[0m.

```js
async () => {
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
        }
```

<hr>/n > Total duration 4826 ms, passes 26 tests, failures 0 tests, pending 0 tests
# TOC
   - [Node Module for Cryptographic Key Utilities in JavaScript](#node-module-for-cryptographic-key-utilities-in-javascript)
     - [PEM RSA key Pair](#node-module-for-cryptographic-key-utilities-in-javascript-pem-rsa-key-pair)
     - [PEM EC key Pair](#node-module-for-cryptographic-key-utilities-in-javascript-pem-ec-key-pair)
<a name=""></a>
 
<a name="node-module-for-cryptographic-key-utilities-in-javascript"></a>
# Node Module for Cryptographic Key Utilities in JavaScript
Default Key Pair generation using crypto.

```js
// This will only work with higher versions of nodejs >=10
const {publicKey, privateKey} = getKeyPair()
assert.isString(publicKey,'public key is not a string');
assert.isString(privateKey,'public key is not a string');
```

<a name="node-module-for-cryptographic-key-utilities-in-javascript-pem-rsa-key-pair"></a>
## PEM RSA key Pair
Generating key pair ....

```js
this._privateKey = new keyutil('create', {type:'rsa', modulusLength:2048, publicExponent:65537});
this._publicKey = new keyutil('jwk', this._privateKey.export('jwk', {outputPublic: true}) )
this._privateKey.encrypt('top secret')
assert.isObject(this._publicKey,'public key is not a object');
assert.isObject(this._privateKey,'public key is not a object');
```

isPrivate of publicKey is False.

```js
assert.isFalse(this._publicKey.isPrivate);
```

isEncrypted of publicKey is False.

```js
assert.isFalse(this._publicKey.isEncrypted);
```

Key type of publicKey is RSA.

```js
assert.equal(this._publicKey.keyType, 'RSA');
```

isPrivate of privateKey is True.

```js
assert.isTrue(this._privateKey.isPrivate);
```

isEncrypted of privateKey is True.

```js
assert.isTrue(this._privateKey.isEncrypted);
```

Decrypt privateKey with wrong password.

```js
assert.throws(()=>this._privateKey.decrypt('just secret'),Error,'DecryptionFailure')
```

Decrypt privateKey with password.

```js
assert.isTrue(this._privateKey.decrypt('top secret'));
```

Key type of privateKey is RSA.

```js
assert.equal(this._privateKey.keyType, 'RSA');
```

Export privateKey as publicKey.

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

Encrypt privateKey with password.

```js
assert.isTrue(this._privateKey.encrypt('top secret'));
```

Sign String with encrypted private key and verify with public key.

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
Generating key pair ....

```js
this._privateKey = new keyutil('create', {type:'ec', namedCurve:'P-256K'});
this._publicKey = new keyutil('jwk', this._privateKey.export('jwk', {outputPublic: true}) )
this._privateKey.encrypt('top secret')
assert.isObject(this._publicKey,'public key is not a object');
assert.isObject(this._privateKey,'public key is not a object');
```

isPrivate of publicKey is False.

```js
assert.isFalse(this._publicKey.isPrivate);
```

isEncrypted of publicKey is False.

```js
assert.isFalse(this._publicKey.isEncrypted);
```

Key type of publicKey is EC.

```js
assert.equal(this._publicKey.keyType, 'EC');
```

isPrivate of privateKey is True.

```js
assert.isTrue(this._privateKey.isPrivate);
```

isEncrypted of privateKey is True.

```js
assert.isTrue(this._privateKey.isEncrypted);
```

Decrypt privateKey with wrong password.

```js
assert.throws(()=>{this._privateKey.decrypt('just secret')},Error,'DecryptionFailure')
```

Decrypt privateKey with password.

```js
assert.isTrue(this._privateKey.decrypt('top secret'));
```

Key type of privateKey is EC.

```js
assert.equal(this._privateKey.keyType, 'EC');
```

Export privateKey as publicKey.

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

Encrypt privateKey with password.

```js
assert.isTrue(this._privateKey.encrypt('new secret'));
```

Export privateKey with password.

```js
privateKey = new keyutil('der', this._privateKey.der); 
originalPrivateKey = new keyutil('pem', this._privateKey.pem); 
assert.deepEqual(privateKey.der,originalPrivateKey.der);
assert.throws(()=>{this._privateKey.jwk},Error,'DecryptionRequired')
```

Sign String with encrypted private key and verify with public key.

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

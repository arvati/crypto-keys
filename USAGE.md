# TOC
   - [Node Module for Cryptographic Key Utilities in JavaScript](#node-module-for-cryptographic-key-utilities-in-javascript)
     - [Using Node Crypto to generate key Pair](#node-module-for-cryptographic-key-utilities-in-javascript-using-node-crypto-to-generate-key-pair)
       - [PEM RSA key Pair](#node-module-for-cryptographic-key-utilities-in-javascript-using-node-crypto-to-generate-key-pair-pem-rsa-key-pair)
       - [PEM EC key Pair](#node-module-for-cryptographic-key-utilities-in-javascript-using-node-crypto-to-generate-key-pair-pem-ec-key-pair)
<a name=""></a>
 
<a name="node-module-for-cryptographic-key-utilities-in-javascript"></a>
# Node Module for Cryptographic Key Utilities in JavaScript
<a name="node-module-for-cryptographic-key-utilities-in-javascript-using-node-crypto-to-generate-key-pair"></a>
## Using Node Crypto to generate key Pair
Default Key Pair generation.

```js
const  options = {modulusLength: 4096, namedCurve: 'secp256k1', publicKeyEncoding: {type: 'spki', format: 'pem'}, privateKeyEncoding: {type: 'pkcs8', format: 'pem'}}
const {publicKey, privateKey} = crypto.generateKeyPairSync('ec', options)
assert.isString(publicKey,'public key is not a string')
assert.isString(privateKey,'public key is not a string');
```

<a name="node-module-for-cryptographic-key-utilities-in-javascript-using-node-crypto-to-generate-key-pair-pem-rsa-key-pair"></a>
### PEM RSA key Pair
Generating key pair ....

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
this._pemPublicKey = publicKey
this._pemPrivateKey = privateKey
this._publicKey = new keyutil('pem', publicKey);
this._privateKey = new keyutil('pem', privateKey);
assert.isObject(this._publicKey,'public key is not a string')
assert.isObject(this._privateKey,'public key is not a string');
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
assert.equal((this._privateKey.export('pem', {outputPublic: true})).replace(/\n$/, ""),this._pemPublicKey.replace(/\n$/, ""))
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

<a name="node-module-for-cryptographic-key-utilities-in-javascript-using-node-crypto-to-generate-key-pair-pem-ec-key-pair"></a>
### PEM EC key Pair
Generating key pair ....

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
this._pemPublicKey = publicKey
this._pemPrivateKey = privateKey
this._publicKey = new keyutil('pem', publicKey);
this._privateKey = new keyutil('pem', privateKey);
assert.isObject(this._publicKey,'public key is not a string')
assert.isObject(this._privateKey,'public key is not a string');
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
assert.throws(()=>this._privateKey.decrypt('just secret'),Error,'DecryptionFailure')
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
assert.equal((this._privateKey.export('pem', {outputPublic: true})).replace(/\n$/, ""),this._pemPublicKey.replace(/\n$/, ""))
```

Encrypt privateKey with password.

```js
assert.isTrue(this._privateKey.encrypt('new secret'));
```

Export privateKey with password.

```js
privateKey = new keyutil('der', this._privateKey.der); 
originalPrivateKey = new keyutil('pem', this._pemPrivateKey); 
originalPrivateKey.decrypt('top secret')
privateKey.decrypt('new secret')
assert.deepEqual(privateKey.jwk,originalPrivateKey.jwk);
```

Sign String with encrypted private key and verify with public key.

```js
async () => {
            //console.info(crypto.getHashes() )
            const value = 'My text to encrypt and verify'
            const privateKey = this._privateKey.pem;
            var signature = crypto.createSign("RSA-SHA256").
                update(value).
                sign({key: privateKey,
                    passphrase: 'new secret',
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


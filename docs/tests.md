---
layout: default
title: Test Results
nav_order: 3
permalink: /tests
---

# Unit Test Results
{:.no_toc}
- TOC
{:toc}

# Node Module for Cryptographic Key Utilities in JavaScript
Default Key Pair generation using crypto ✓.
3ms.

```js
// This will only work with higher versions of nodejs >=10
const {publicKey, privateKey} = getKeyPair()
assert.isString(publicKey,'public key is not a string');
assert.isString(privateKey,'public key is not a string');
```

## PEM RSA key Pair
Generating key pair ... ✓.
3.426s.

```js
this._privateKey = new keyutil('create', {type:'rsa', modulusLength:2048, publicExponent:65537});
this._publicKey = new keyutil('jwk', this._privateKey.export('jwk', {outputPublic: true}) )
this._privateKey.encrypt('top secret')
assert.isObject(this._publicKey,'public key is not a object');
assert.isObject(this._privateKey,'public key is not a object');
```

isPrivate of publicKey is False ✓.
0ms.

```js
assert.isFalse(this._publicKey.isPrivate);
```

isEncrypted of publicKey is False ✓.
0ms.

```js
assert.isFalse(this._publicKey.isEncrypted);
```

Key type of publicKey is RSA ✓.
0ms.

```js
assert.equal(this._publicKey.keyType, 'RSA');
```

isPrivate of privateKey is True ✓.
0ms.

```js
assert.isTrue(this._privateKey.isPrivate);
```

isEncrypted of privateKey is True ✓.
0ms.

```js
assert.isTrue(this._privateKey.isEncrypted);
```

Decrypt privateKey with wrong password ✖.
32ms.

```js
assert.throws(()=>this._privateKey.decrypt('just secret'),Error,'DecryptionFailure')
```

Decrypt privateKey with password ✖.
27ms.

```js
assert.isTrue(this._privateKey.decrypt('top secret'));
```

Key type of privateKey is RSA ✓.
0ms.

```js
assert.equal(this._privateKey.keyType, 'RSA');
```

Export privateKey as publicKey ✓.
37ms.

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

Encrypt privateKey with password ✖.
24ms.

```js
assert.isTrue(this._privateKey.encrypt('top secret'));
```

Sign String with encrypted private key and verify with public key ✓.
5ms.

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

## PEM EC key Pair
Generating key pair ... ✓.
132ms.

```js
this._privateKey = new keyutil('create', {type:'ec', namedCurve:'P-256K'});
this._publicKey = new keyutil('jwk', this._privateKey.export('jwk', {outputPublic: true}) )
this._privateKey.encrypt('top secret')
assert.isObject(this._publicKey,'public key is not a object');
assert.isObject(this._privateKey,'public key is not a object');
```

isPrivate of publicKey is False ✓.
0ms.

```js
assert.isFalse(this._publicKey.isPrivate);
```

isEncrypted of publicKey is False ✓.
0ms.

```js
assert.isFalse(this._publicKey.isEncrypted);
```

Key type of publicKey is EC ✓.
0ms.

```js
assert.equal(this._publicKey.keyType, 'EC');
```

isPrivate of privateKey is True ✓.
0ms.

```js
assert.isTrue(this._privateKey.isPrivate);
```

isEncrypted of privateKey is True ✓.
0ms.

```js
assert.isTrue(this._privateKey.isEncrypted);
```

Decrypt privateKey with wrong password ✖.
18ms.

```js
assert.throws(()=>{this._privateKey.decrypt('just secret')},Error,'DecryptionFailure')
```

Decrypt privateKey with password ✖.
25ms.

```js
assert.isTrue(this._privateKey.decrypt('top secret'));
```

Key type of privateKey is EC ✓.
0ms.

```js
assert.equal(this._privateKey.keyType, 'EC');
```

Export privateKey as publicKey ✓.
34ms.

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

Encrypt privateKey with password ✖.
17ms.

```js
assert.isTrue(this._privateKey.encrypt('new secret'));
```

Export privateKey with password ✖.
4ms.

```js
privateKey = new keyutil('der', this._privateKey.der); 
originalPrivateKey = new keyutil('pem', this._privateKey.pem); 
assert.deepEqual(privateKey.der,originalPrivateKey.der);
assert.throws(()=>{this._privateKey.jwk},Error,'DecryptionRequired')
```

Sign String with encrypted private key and verify with public key ✓.
4ms.

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



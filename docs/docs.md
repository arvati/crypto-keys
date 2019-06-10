---
layout: default
title: API
nav_order: 2
permalink: /docs
---

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
        * [.keyType](#module_crypto-keys--Key+keyType) ⇒ <code>string</code>
        * [.jwkThumbprint](#module_crypto-keys--Key+jwkThumbprint) ⇒
        * [.export([format], [options])](#module_crypto-keys--Key+export) ⇒ <code>string</code> \| <code>Uint8Array</code> \| <code>jwk</code>
        * [.encrypt(passphrase)](#module_crypto-keys--Key+encrypt) ⇒ <code>Class</code>
        * [.decrypt(passphrase)](#module_crypto-keys--Key+decrypt) ⇒ <code>Class</code>
        * [.getJwkThumbprint([alg], [output])](#module_crypto-keys--Key+getJwkThumbprint) ⇒ <code>Uint8Array</code> \| <code>string</code>

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
<a name="module_crypto-keys--Key+keyType"></a>

#### key.keyType ⇒ <code>string</code>
Get Jwk key type of decrypted keys

**Kind**: instance property of [<code>Key</code>](#exp_module_crypto-keys--Key)  
**Returns**: <code>string</code> - - key type 'EC' or 'RSA'  
<a name="module_crypto-keys--Key+jwkThumbprint"></a>

#### key.jwkThumbprint ⇒
Get Jwk Thumbprint of the key with default parameters alg='SHA-256', output='binary'

**Kind**: instance property of [<code>Key</code>](#exp_module_crypto-keys--Key)  
**Returns**: Jwk Thumbprint of the key  
<a name="module_crypto-keys--Key+export"></a>

#### key.export([format], [options]) ⇒ <code>string</code> \| <code>Uint8Array</code> \| <code>jwk</code>
Export Key as format.

**Kind**: instance method of [<code>Key</code>](#exp_module_crypto-keys--Key)  
**Returns**: <code>string</code> \| <code>Uint8Array</code> \| <code>jwk</code> - - Key in 'der', 'pem' or 'jwk' format  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| [format] | <code>string</code> | <code>&quot;&#x27;jwk&#x27;&quot;</code> | Format of key to export ('der', 'pem' or 'jwk') |
| [options] | <code>Object</code> | <code>{}</code> | Options to export key into format only with decrypted keys |
| [options.encryptParams] | <code>Object</code> | <code>{}</code> | Options to export encrypted prvate key for 'pem' and 'der' formats |
| [options.encryptParams.passphrase] | <code>string</code> | <code>&quot;&#x27;&#x27;&quot;</code> | Passphrase to encrypt private key |
| [options.encryptParams.algorithm] | <code>string</code> | <code>&quot;&#x27;pbes2&#x27;&quot;</code> | if 'pbes2' only pbkdf2 and salt length of 8 is available, choose from 'pbeWithMD5AndDES-CBC', 'pbeWithSHA1AndDES-CBC', 'pbes2' |
| [options.encryptParams.iterationCount] | <code>integer</code> | <code>2048</code> | Iteration count to use for salt algorithm |
| [options.encryptParams.cipher] | <code>string</code> | <code>&quot;&#x27;aes256-cbc&#x27;&quot;</code> | Cipher when algorithm is 'pbes2', choose from 'des-ede3-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc' |
| [options.encryptParams.prf] | <code>string</code> | <code>&quot;&#x27;hmacWithSHA256&#x27;&quot;</code> | Prf when algorithm is 'pbes2', choose from 'hmacWithSHA1', 'hmacWithSHA256', 'hmacWithSHA384', 'hmacWithSHA512' |
| [options.outputPublic] | <code>boolean</code> |  | True to Export public key from private Key or undefined/False to maintain actual format |
| [options.compact] | <code>boolean</code> | <code>false</code> | Export compact key for 'EC' type keys |

<a name="module_crypto-keys--Key+encrypt"></a>

#### key.encrypt(passphrase) ⇒ <code>Class</code>
Encrypt Private Key using default parameters.

**Kind**: instance method of [<code>Key</code>](#exp_module_crypto-keys--Key)  
**Chainable**  
**Returns**: <code>Class</code> - this - Key for channing  

| Param | Type | Description |
| --- | --- | --- |
| passphrase | <code>string</code> | Passphrase to encrypt private key |

<a name="module_crypto-keys--Key+decrypt"></a>

#### key.decrypt(passphrase) ⇒ <code>Class</code>
Decrypt Private Key using default parameters.

**Kind**: instance method of [<code>Key</code>](#exp_module_crypto-keys--Key)  
**Chainable**  
**Returns**: <code>Class</code> - this - Key for channing  

| Param | Type | Description |
| --- | --- | --- |
| passphrase | <code>string</code> | Passphrase to decrypt private key |

<a name="module_crypto-keys--Key+getJwkThumbprint"></a>

#### key.getJwkThumbprint([alg], [output]) ⇒ <code>Uint8Array</code> \| <code>string</code>
Get Jwk Thumbprint of decrypted keys

**Kind**: instance method of [<code>Key</code>](#exp_module_crypto-keys--Key)  
**Returns**: <code>Uint8Array</code> \| <code>string</code> - - Jwk Thumbprint of the key in format  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| [alg] | <code>string</code> | <code>&quot;&#x27;SHA-256&#x27;&quot;</code> | Hash algorithm, choose from 'SHA-256','SHA-384','SHA-512' and 'SHA-1, 'MD5' that SHOULD NOT USE |
| [output] | <code>string</code> | <code>&quot;&#x27;binary&#x27;&quot;</code> | Output Format 'binary', 'hex', 'base64' |


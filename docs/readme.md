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

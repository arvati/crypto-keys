---
layout: default
title: Home
nav_order: 1
permalink: /
description: Node.js javascript tool to generate ,encrypt and decrypt RSA and EC keys formated as PEM / DER.
nav_exclude: false
search_exclude: true
has_toc: true
---

# Crypto Keys
{:.no_toc .fs-9 }
Node.js javascript tool to generate ,encrypt and decrypt RSA and EC keys formated as PEM / DER.
{: .fs-6 .fw-300 }

[Get started now](#getting-started){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 } [View it on GitHub](https://github.com/arvati/crypto-keys){: .btn .fs-5 .mb-4 .mb-md-0 }

- TOC
{:toc}


## Getting started
This is a fork of [js-crypto-key-utils](https://www.npmjs.com/package/js-crypto-key-utils) to work only with node.js,  with less dependencies and not available for Octet-Formatted Key.    

Included code to generate private and public key pair with RSA or EC algorithm

### Usage
Supported key types are PEM/DER.   
 * Public keys are encoded to the form of SubjectPublicKeyInfo (SPKI) defined as a part of X.509 public key certificate ([RFC5280](https://tools.ietf.org/html/rfc5280)). The detailed encoding rule for elliptic curve cryptographic keys is given in RFC5480. 
 * Private keys are encoded to hte form of PrivateKeyInfo defined in PKCS#8 ([RFC5958](https://tools.ietf.org/html/rfc5958)). The detailed encoding rule for elliptic curve cryptographic keys is given in [RFC5915](https://tools.ietf.org/html/rfc5915)  as well as SPKI. 

Please refer to [RFC3447](https://tools.ietf.org/html/rfc3447)  for the detailed encoding rule of RSA public and private keys.

See our [API](docs) and [Tests Results](tests) for examples of usage.

## About the project

Crypto-Keys is &copy; 2019-2019 by [Ademar Arvati](https://github.com/arvati).

### License

Crypto-Keys  is distributed by an [MIT license](https://github.com/arvati/crypto-keys/tree/master/LICENSE.md).

### Contributing

When contributing to this repository, please first discuss the change you wish to make via issue with the owners of this repository before making a change. Read more about becoming a contributor in [our GitHub repo](https://github.com/arvati/crypto-keys#contributing).

## Credits
This fork is totally based on work published by [junkurihara](https://github.com/junkurihara) at [js-crypto-key-utils](https://github.com/junkurihara/jscu/tree/master/packages/js-crypto-key-utils)

It uses library publish by [Tom Wu](mailto:tjw@cs.Stanford.EDU) at [stanford jsbn](http://www-cs-students.stanford.edu/~tjw/jsbn/) to generate keypair in pure js.

Using Great Jekyll theme [Just the Docs](https://github.com/pmarsceill/just-the-docs) by [Patrick Marsceill](http://patrickmarsceill.com/)




# ZPI IFIND

[![Build Status](https://travis-ci.org/bakaoh/zpi-ifind.svg?branch=master)](https://travis-ci.org/bakaoh/zpi-ifind) [![npm version](https://badge.fury.io/js/zpi-ifind.svg)](https://badge.fury.io/js/zpi-ifind)

## Usage

1. Install package

```bash
$ npm i zpi-ifind
```

2. Generate key

```node
const { generateKey } = require('zpi-ifind');
generateKey('ifind.private.pem', 'ifind.public.pem');
```

3. Exchange public key file with zpi

4. Get data from query param `d`

```node
let data = req.query.d;
```

5. Decrypt and verify data to get user info

```node
const {
    loadPrivateKey,
    loadPublicKey,
    decryptAndVerify
} = require('zpi-ifind');

const ifindPrivate = loadPrivateKey('ifind.private.pem');
const zpiPublic = loadPublicKey('zpi.public.pem');

const message = decryptAndVerify(
    data,
    ifindPrivate,
    zpiPublic
);
```
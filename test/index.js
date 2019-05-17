import { assert } from 'chai';
import fs from 'fs';
import semver from 'semver';
import {
  generateKey,
  loadPrivateKey,
  loadPublicKey,
  signAndEncrypt,
  decryptAndVerify
} from '../src';

const message = '{"phone":"0966333444","expired_time":1555661758}';
const data = '2LkPekZVsVu9wV8rmkwfKxdiXvydf5aM7NfN1WJ9nQERBwtdtQUHFNYw5RoZoLjpCSGYqeZmAXvpoYxsHWbbXWJRBxVguHoRV5GXxbaZJkebgGGCcSEk6tW1K4P7pQjVtC8uFRJ7L2wkVodv1tDFdF9tLmBfv42Q5s4pYvDjZzS89weRihWnDra6H6X9gR3W2FAUUHvAhK777N8XwFNVp3FWK8XfvuAcj1crFanrf34XHPDShPHE5ftzwoMFd7TgXhALE5kRjYoSzEpcJxBvbmKx5VzkDJtKPh9neNLBwwTVumddQPuxpgNKp2JADKVrSAojmkKTispuBvsevSUqmbHTobt1uTi5Rc21RKp2MDHhgtD3xPHZY82VTHSjamPGJqu3AEkHcfnyfrZ65GNJ728A7R9GueF7fPgxLRyG8yEbtow3C5VyYmkx7qUCDkzzniYsd6EGz5DudjVWNJkwQuh7MuJsSuAF4XsJvu8RFd3tx2ayHUyNF2umQQXma1cYK9nGTEgi7oSih9jcyMqLq4AGbgf1vRNUg4WNtf3KxG47GXPzv64qJDsUjmuSxD7uMCm7UPxV64A9dCq5MThtC37YRM6qiUHoyoZyyZbv5rkRSsJDcSsYrJ6ECJXuSFC725CY8bGTvHRT8r7p1sRkLvWyaTxnZzbrNTYjiMd2xDko6FSaGNbjRdaoa2U3_2k7GGDc66GAvQwX13t8i7HYeEd8V8j6vY47yzXeJqA48bD6u4GuVsAhKfhkVLbHwow81P1ay9ZawRJurwTkxXXEG3tBsoAQ1GWuP6nWoF8tAdUP1F4nouxZXmZ63L3ckRU9cFaXF7WV7tWw2dbiEE4P2k833AhGmSu5sWZduxAtY2UHiYcVpyd2jXvUSqvJyd1eJx6drHZGG5mwLfQFa1EaGXrceBn79hEvE7fDwBKNtpSmDToTjk9Px6mxc4h2sUtKhEsoYYN4Suqyq4n5MRXxVvuw3bJuFn4u6FE9oSztTXB3185dmSCst8vUzXiEHPkJfSM4h79BLSkLf6BxppfvaZpX8nToNrUSbfZ8cyRCCmPawYHvhrS8Ud3ddSpN6jFKjCV4zrBPfothcqmnq7c4CZvkV4a4smePieF9cHfyu9dbyALx9ymbxLbALvTNJjQfqNYjZ7gT4UwwUe2iNipkgJ2hQeaYy1eUseb6vN1XPc8pzgxJSKSqk3mbDLTPquGhk3CacKCB9ymzSRgeigKmFZKtTxGehAhMT1FX64o4AZ44HA3xTDvCts1kbp2JQy8QUMhnirjV7JZC9UbSQnd55y2cgc1oaZQgVqa8P9pF9LkFee5wLSJNb3SGhnMdjjCMtQ6qM6ZxV2bAXDxciGmoaAxC6Yi6AFcmyyWazK8XiEx51DuGj7DCg2YrF';

describe('Generate', () => {
  it('should write public and private key to files', () => {
    const privateFile = 'testdata/new/private.pem';
    const publicFile = 'testdata/new/public.pem';
    if (fs.existsSync(privateFile)) fs.unlinkSync(privateFile);
    if (fs.existsSync(publicFile)) fs.unlinkSync(publicFile);

    if (semver.gte(process.version, '10.12.0')) {
      generateKey(privateFile, publicFile);
      assert(fs.existsSync(privateFile));
      assert(fs.existsSync(publicFile));
    } else {
      const gk = () => generateKey(privateFile, publicFile);
      assert.throws(gk, Error, 'Requires nodejs >= v10.12.0');
    }
  });
});

describe('Encrypt', () => {
  it('should return not empty data', () => {
    const receiverPublic = loadPublicKey('testdata/ifind/public.pem');
    const senderPrivate = loadPrivateKey('testdata/zpi/private.pem');

    const d = signAndEncrypt(
      message,
      receiverPublic,
      senderPrivate
    );

    assert.isNotEmpty(d);
  });
});

describe('Decrypt', () => {
  it('should return expected message', () => {
    const receiverPrivate = loadPrivateKey('testdata/ifind/private.pem');
    const senderPublic = loadPublicKey('testdata/zpi/public.pem');

    const msg = decryptAndVerify(
      data,
      receiverPrivate,
      senderPublic
    );

    assert(msg === message);
  });

  it('should throw exception when signature does not match', () => {
    const receiverPrivate = loadPrivateKey('testdata/ifind/private.pem');
    const senderPublic = loadPublicKey('testdata/zpi/public.pem');

    const dav = () => decryptAndVerify(
      `3${data.slice(1)}`,
      receiverPrivate,
      senderPublic
    );

    assert.throws(dav, Error, 'Signature does not match');
  });

  it('should throw exception when invalid format', () => {
    const receiverPrivate = loadPrivateKey('testdata/ifind/private.pem');
    const senderPublic = loadPublicKey('testdata/zpi/public.pem');

    const dav = () => decryptAndVerify(
      `${data.replace('_', '+')}`,
      receiverPrivate,
      senderPublic
    );

    assert.throws(dav, Error, 'Invalid format');
  });
});

import { assert } from 'chai';
import {
  loadPrivateKey,
  loadPublicKey,
  signAndEncrypt,
  decryptAndVerify
} from '../src';

const message = '{"phone":"0966333444","expired_time":1555661758}';
const data = '2LkPekZVsVu9wV8rmkwfKxdiXvydf5aM7NfN1WJ9nQERBwtdtQUHFNYw5RoZoLjpCSGYqeZmAXvpoYxsHWbbXWJRBxVguHoRV5GXxbaZJkebgGGCcSEk6tW1K4P7pQjVtC8uFRJ7L2wkVodv1tDFdF9tLmBfv42Q5s4pYvDjZzS89weRihWnDra6H6X9gR3W2FAUUHvAhK777N8XwFNVp3FWK8XfvuAcj1crFanrf34XHPDShPHE5ftzwoMFd7TgXhALE5kRjYoSzEpcJxBvbmKx5VzkDJtKPh9neNLBwwTVumddQPuxpgNKp2JADKVrSAojmkKTispuBvsevSUqmbHTobt1uTi5Rc21RKp2MDHhgtD3xPHZY82VTHSjamPGJqu3AEkHcfnyfrZ65GNJ728A7R9GueF7fPgxLRyG8yEbtow3C5VyYmkx7qUCDkzzniYsd6EGz5DudjVWNJkwQuh7MuJsSuAF4XsJvu8RFd3tx2ayHUyNF2umQQXma1cYK9nGTEgi7oSih9jcyMqLq4AGbgf1vRNUg4WNtf3KxG47GXPzv64qJDsUjmuSxD7uMCm7UPxV64A9dCq5MThtC37YRM6qiUHoyoZyyZbv5rkRSsJDcSsYrJ6ECJXuSFC725CY8bGTvHRT8r7p1sRkLvWyaTxnZzbrNTYjiMd2xDko6FSaGNbjRdaoa2U3SYjbp1TCe3CdgFEKn5WNVdQYTrTvVq7CsKjj6f24uA23QT8WGYfF7rLWcKwKoceCHxkWYXtnnVsVPvV9H4CdEXqV3SPwJqQY7vGVZHho5nw1DuUkAxJb8qeGRudeUxhDQdyXNxmYqNZVv81gVoFRUjrsvt92hoRsqTRFkhdwZMZ9PxtcBR4NS6zQ7drefKFfoDkZjVHUiQfFdnZC5ZgU8RiWzE3QFGjDRhYFfWgMnbmYVkszkNMbvuTWS1EwxvLhXYXzx1pHs6Ty94LycGxRC5zU8rnQYup5mqkg9fF7riBh42nNfQHApevtyZmM5bfrUYwvrvsPC76KTNnwn1MaiiUt7obTjSVuZxt65NRH6Hcj7fYb5W3opSNuz6kwcZcrTgJbedJrjJnpc1FJd4oGzkpxKaUQDPW1xiBf3g4JS5JNkz4kKecqiYmT6KYvyH2SdhvvuGNpy1Q6cEtXwYLyK1HxvekfPQADeJMPVkXQmGaL5Gpz5aTrtqNeGcV9sb53iLgh5vqv4miWvd8JxiQgjeLssmp6DrpfNtSArxcWaw7RBztVNFxdfzUjmRFBy9JPXfLJPPLV8FPErmc8W13DbqPnrSesSkKAzU4foNLC9mVuJ6YGSppE617bVwxVMCca8hWuCAFMSVoZ6TXBLH9SA4M4V1MD7HYioinKbbdPL6Hk1DdPthhpA1q5r4P';

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
});

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
const data = 'h18XD8D94yz4RCYcXLpARbL1aVSJk4cEwtZerrVNxubs333E9GHH14DQc2QaVH7NDuSMaoFMBg1qtx5m5C8aNnBTmh4oQgv5CMLyNJjDzmpP7e94DqhUsHzLdwR3C2VDAir7TWmM5asxa3ABwZtm3xhp6Fh7ut4GNdbHjyKAegD4N2LgdrUSfjR5cr9wRTCr3mry6gkRfjS2vtgJTQj2GM63KeEWY4uBKAEYjB8JXHbq3JDCUUtxox9psEKjUqx4yYj5v3rqmWtNn7emt8m2CNJapr6Efb6N7cHUmSfVLyELV5zY9UgwGzh38hW8KUNS2HeJF1Y6Mt9FT1EjZRbHQHvYLJUo7rF2EnBWXxWpL9tt1tTMrVb7K5XAMWSZJa1kiPVQVXCG4odGSRgXF3jTxpm7Re744SVFoQbt5nyLxk2HCmKtKP8WGzxygyEo9J5QTBLPWPLCCYKA8RANhKBjrjmkkTDgBMi4AC7X2wyhAAGF5xgH5DXCMgifkzyQLUFJeq5n1FUsPfi1dnGWVUukgvuxDN8Vx5N5fqMGR7KNeJPdFU4AkK4DcstW81gKHUNssTmxJS9VjK6KutC5Paxx1npAZmKUvZkXdzirpjV9S7Emt3QdgG8arF6dqPwQM2QQifNCC2hopVQumFWJy9eN7dPLSF1mg2V5LiTdCWg3SrjAdTkUQgFcuY7cMfF_34GzVfrKyT9aRL9y6kKciykMpbZsE4jhHsRvwPtF6oXjkyQmr5WxsEGjyQAZ6bZc4K9JCjKMb8DQR14756PuMHJceZ4kMYuKetBt61Md6BcwWfBBjeEWX7cTkPFWShmKhrY5v3fHbsKNCLhxMF4qgNfDQjALS6X3n9BVMe2wRwB2hg4sj6AH5Jg6wjeUNczL3NxxANYyMd1dayixVKySAMXrvmFnGFdCimvX7TeA1q3v2Vj4dQQm9ewG6VVy5uhiaN9Ci9c3KCsp3XivCNpgco4RoY653EcggbUuUkmAixxb8C522bF311sZEWe3YRTpDXgYfz4Bfa9nkVZzzLXY95tzjaewWuufZYURpf9sv7CpaiFep24rYzUtdbLVm269uE7fSTQzSoKzLDodE31aak7buFvb9egqV2wWF3c4TdHjRXiNdgCqSv5JKWfh9G6dThZZKXHDr1H4nts4CnHXNmTCeNaqDCGY1qkt4wHTxRNvYDdTxPiWDoffGq3iJpkv6BsXKxzKtzVW4bCAYYBfY1SCEDvw4GJt484PFfPVrVdLAAmFhAHZRR1DZu9a3RUypLhADr7kH2p5xzuNMjzE2ZEEjCFMoNUMc8ah8UwMz8W4Uu1bUDvht5UsNwDErFdqgXCqfbAQzjievijAmkNzzLKQuo2DvnAFhYVje5yWaBLi26GxcUnQhDiYjV2t';

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
      `${data.replace("_","+")}`,
      receiverPrivate,
      senderPublic
    );

    assert.throws(dav, Error, 'Invalid format');
  });
});

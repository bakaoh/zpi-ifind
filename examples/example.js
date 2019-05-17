/* eslint-disable no-console */
const {
  loadPrivateKey,
  loadPublicKey,
  decryptAndVerify
} = require('../lib');

const data = 'h18XD8D94yz4RCYcXLpARbL1aVSJk4cEwtZerrVNxubs333E9GHH14DQc2QaVH7NDuSMaoFMBg1qtx5m5C8aNnBTmh4oQgv5CMLyNJjDzmpP7e94DqhUsHzLdwR3C2VDAir7TWmM5asxa3ABwZtm3xhp6Fh7ut4GNdbHjyKAegD4N2LgdrUSfjR5cr9wRTCr3mry6gkRfjS2vtgJTQj2GM63KeEWY4uBKAEYjB8JXHbq3JDCUUtxox9psEKjUqx4yYj5v3rqmWtNn7emt8m2CNJapr6Efb6N7cHUmSfVLyELV5zY9UgwGzh38hW8KUNS2HeJF1Y6Mt9FT1EjZRbHQHvYLJUo7rF2EnBWXxWpL9tt1tTMrVb7K5XAMWSZJa1kiPVQVXCG4odGSRgXF3jTxpm7Re744SVFoQbt5nyLxk2HCmKtKP8WGzxygyEo9J5QTBLPWPLCCYKA8RANhKBjrjmkkTDgBMi4AC7X2wyhAAGF5xgH5DXCMgifkzyQLUFJeq5n1FUsPfi1dnGWVUukgvuxDN8Vx5N5fqMGR7KNeJPdFU4AkK4DcstW81gKHUNssTmxJS9VjK6KutC5Paxx1npAZmKUvZkXdzirpjV9S7Emt3QdgG8arF6dqPwQM2QQifNCC2hopVQumFWJy9eN7dPLSF1mg2V5LiTdCWg3SrjAdTkUQgFcuY7cMfF_34GzVfrKyT9aRL9y6kKciykMpbZsE4jhHsRvwPtF6oXjkyQmr5WxsEGjyQAZ6bZc4K9JCjKMb8DQR14756PuMHJceZ4kMYuKetBt61Md6BcwWfBBjeEWX7cTkPFWShmKhrY5v3fHbsKNCLhxMF4qgNfDQjALS6X3n9BVMe2wRwB2hg4sj6AH5Jg6wjeUNczL3NxxANYyMd1dayixVKySAMXrvmFnGFdCimvX7TeA1q3v2Vj4dQQm9ewG6VVy5uhiaN9Ci9c3KCsp3XivCNpgco4RoY653EcggbUuUkmAixxb8C522bF311sZEWe3YRTpDXgYfz4Bfa9nkVZzzLXY95tzjaewWuufZYURpf9sv7CpaiFep24rYzUtdbLVm269uE7fSTQzSoKzLDodE31aak7buFvb9egqV2wWF3c4TdHjRXiNdgCqSv5JKWfh9G6dThZZKXHDr1H4nts4CnHXNmTCeNaqDCGY1qkt4wHTxRNvYDdTxPiWDoffGq3iJpkv6BsXKxzKtzVW4bCAYYBfY1SCEDvw4GJt484PFfPVrVdLAAmFhAHZRR1DZu9a3RUypLhADr7kH2p5xzuNMjzE2ZEEjCFMoNUMc8ah8UwMz8W4Uu1bUDvht5UsNwDErFdqgXCqfbAQzjievijAmkNzzLKQuo2DvnAFhYVje5yWaBLi26GxcUnQhDiYjV2t';

try {
  const receiverPrivate = loadPrivateKey('testdata/ifind/private.pem');
  const senderPublic = loadPublicKey('testdata/zpi/public.pem');

  const message = decryptAndVerify(
    data,
    receiverPrivate,
    senderPublic
  );

  const info = JSON.parse(message);
  console.log('Phone:', info.phone);
  console.log('Expired Time:', info.expired_time);
} catch (err) {
  console.error(err);
}

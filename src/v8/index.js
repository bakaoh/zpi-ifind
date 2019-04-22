const fs = require('fs');
const base58 = require('bs58');
const NodeRSA = require('node-rsa');

const SIGN_LEN = 700;

const generateKey = (privateFile, publicFile) => {
  const key = new NodeRSA({ b: 1024 });
  fs.writeFileSync(privateFile, key.exportKey('pkcs1-private-pem'));
  fs.writeFileSync(publicFile, key.exportKey('pkcs1-public-pem'));
};

const loadPrivateKey = filePath => new NodeRSA(
  fs.readFileSync(filePath),
  'pkcs1-private-pem',
  { encryptionScheme: 'pkcs1', signingScheme: 'sha512' }
);

const loadPublicKey = filePath => new NodeRSA(
  fs.readFileSync(filePath),
  'pkcs1-public-pem',
  { encryptionScheme: 'pkcs1', signingScheme: 'sha512' }
);

const encrypt = (message, publicKey) => {
  const encMessBuffer = publicKey.encrypt(Buffer.from(message));
  return base58.encode(encMessBuffer);
};

const decrypt = (text, privateKey) => {
  const message = privateKey.decrypt(base58.decode(text));
  return message.toString('utf8');
};

const sign = (message, privateKey) => {
  const signature = privateKey.sign(Buffer.from(message));
  return base58.encode(Buffer.from(signature));
};

const verify = (message, signature, publicKey) => {
  const sigBytes = base58.decode(signature);
  return publicKey.verify(Buffer.from(message), sigBytes);
};

const signAndEncrypt = (message, receiverPublicKey, senderPrivateKey) => {
  const encMess = encrypt(message, receiverPublicKey);
  const sig = sign(message, senderPrivateKey);
  return sig + encMess;
};

const decryptAndVerify = (text, receiverPrivateKey, senderPublicKey) => {
  const sig = text.slice(0, SIGN_LEN);
  const encMess = text.slice(SIGN_LEN, text.length);
  const message = decrypt(encMess, receiverPrivateKey);
  if (verify(message, sig, senderPublicKey) === false) {
    throw new Error('Signature does not match');
  }
  return message;
};

export {
  generateKey,
  loadPrivateKey,
  loadPublicKey,
  signAndEncrypt,
  decryptAndVerify,
};

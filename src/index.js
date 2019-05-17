const crypto = require('crypto');
const fs = require('fs');
const base58 = require('bs58');

const generateKey = (privateFile, publicFile) => {
  if (typeof crypto.generateKeyPairSync !== 'function') {
    throw new Error('Requires nodejs >= v10.12.0');
  }
  const key = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: 'pkcs1',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs1',
      format: 'pem'
    }
  });

  fs.writeFileSync(privateFile, key.privateKey);
  fs.writeFileSync(publicFile, key.publicKey);
};

const loadPrivateKey = filePath => (typeof crypto.createPrivateKey === 'function'
  ? crypto.createPrivateKey({
    key: fs.readFileSync(filePath),
    format: 'pem',
    type: 'pkcs1',
    passphrase: ''
  }) : fs.readFileSync(filePath));

const loadPublicKey = filePath => (typeof crypto.createPublicKey === 'function'
  ? crypto.createPublicKey({
    key: fs.readFileSync(filePath),
    format: 'pem',
    type: 'pkcs1'
  }) : fs.readFileSync(filePath));

const encrypt = (message, publicKey) => {
  const encMessBuffer = crypto.publicEncrypt({
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_PADDING
  }, Buffer.from(message));
  return base58.encode(encMessBuffer);
};

const decrypt = (text, privateKey) => {
  const buff = base58.decode(text);
  const message = crypto.privateDecrypt({
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PADDING
  }, buff);
  return message.toString('utf8');
};

const sign = (message, privateKey) => {
  const signInstance = crypto.createSign('SHA512');
  signInstance.write(message);
  signInstance.end();
  const signature = signInstance.sign(privateKey);
  return base58.encode(signature);
};

const verify = (message, signature, publicKey) => {
  const verifyInstance = crypto.createVerify('SHA512');
  verifyInstance.write(message);
  verifyInstance.end();
  const sigBytes = base58.decode(signature);
  return verifyInstance.verify(publicKey, sigBytes);
};

const signAndEncrypt = (message, receiverPublicKey, senderPrivateKey) => {
  const encMess = encrypt(message, receiverPublicKey);
  const sig = sign(message, senderPrivateKey);
  return `${sig}_${encMess}`;
};

const decryptAndVerify = (text, receiverPrivateKey, senderPublicKey) => {
  const parts = text.split('_');
  if (parts.length !== 2) {
    throw new Error('Invalid format');
  }
  const sig = parts[0];
  const encMess = parts[1];
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

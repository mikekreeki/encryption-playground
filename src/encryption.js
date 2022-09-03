import argon2 from 'argon2-wasm-pro';
import nacl from 'tweetnacl';
import util from 'tweetnacl-util';

const KEY_SIZE = 32; // 32-byte keys
const NONCE_SIZE = 24;

export const generateHash = async (pass, salt) => {
  const { hash } = await argon2.hash({
    hashLen: 32,
    time: 1000,
    mem: 1024,
    type: argon2.argon2id,
    pass,
    salt,
  });

  return util.encodeBase64(hash);
};

export const generateKeys = (hash) => {
  const keyPair = nacl.box.keyPair.fromSecretKey(util.decodeBase64(hash));

  return {
    publicKey: util.encodeBase64(keyPair.publicKey),
    privateKey: util.encodeBase64(keyPair.secretKey),
  };
};

export const encryptString = (publicKey, message) => {
  const ephemeralKeyPair = nacl.box.keyPair();
  const publicKeyUInt8Array = util.decodeBase64(publicKey);

  const messageUInt8Array = util.decodeUTF8(message);
  const nonce = nacl.randomBytes(NONCE_SIZE);

  const ciphertextUInt8Array = nacl.box(
    messageUInt8Array,
    nonce,
    publicKeyUInt8Array,
    ephemeralKeyPair.secretKey,
  );

  const encrypted = new Uint8Array([
    ...ephemeralKeyPair.publicKey,
    ...nonce,
    ...ciphertextUInt8Array,
  ]);

  return util.encodeBase64(encrypted);
};

export const decryptString = (privateKey, message) => {
  const receiverSecretKeyUint8Array = util.decodeBase64(privateKey);
  const decoded = util.decodeBase64(message);

  const ephemPubKey = decoded.slice(0, KEY_SIZE);
  const decodedNonce = decoded.slice(KEY_SIZE, KEY_SIZE + NONCE_SIZE);

  const ciphertext = decoded.slice(KEY_SIZE + NONCE_SIZE, decoded.length);

  const decrypted = nacl.box.open(
    ciphertext,
    decodedNonce,
    ephemPubKey,
    receiverSecretKeyUint8Array,
  );

  return util.encodeUTF8(decrypted);
};

const {assert} = require('chai');
const {utils} = require('@aeternity/aeproject');
const {generateMnemonic, mnemonicToSeed} = require('@aeternity/bip39');
const {getHdWalletAccountFromSeed, derivePathFromSeed, derivePathFromKey, getKeyPair} = require("@aeternity/aepp-sdk");
const {SignJWT, jwtVerify, importPKCS8, importJWK, exportJWK} = require('jose')
const {subtle} = require('crypto').webcrypto;
const crypto = require('crypto');
const {encodeBase64} = require('tweetnacl-util');
const asn1 = require('asn1.js');
const ecKeyUtils = require('eckey-utils');

describe('JWT Auth', () => {
    let aeSdk;
    let contract;

    before(async () => {
        //aeSdk = utils.getSdk();

        // create a snapshot of the blockchain state
        //await utils.createSnapshot(aeSdk);
    });

    // after each test roll back to initial state
    afterEach(async () => {
        //await utils.rollbackSnapshot(aeSdk);
    });


    it('generate key', async () => {
        const mnemonic = generateMnemonic();
        const seed = mnemonicToSeed(mnemonic)

        const naclWalletKey = derivePathFromSeed('m/44h/457h', seed);
        const naclDerived = derivePathFromKey(`0h/0h/0h`, naclWalletKey);
        const naclKeyPair = getKeyPair(naclDerived.secretKey);

        const aeKeyPair = getHdWalletAccountFromSeed(seed, 0);
        console.log(naclKeyPair, aeKeyPair)

        const jwk = {
            kty: "OKP",
            crv: "Ed25519",
            d: encodeBase64(naclKeyPair.secretKey.subarray(0, 32)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
            x: encodeBase64(naclKeyPair.publicKey).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
        };

        const jwt = await new SignJWT({'user_id': '@user:shtest'})
            .setProtectedHeader({alg: 'EdDSA', typ: 'JWT'})
            .setExpirationTime('2h')
            .sign(await importJWK(jwk, 'EdDSA'))

        console.log(jwt)

        const publicKey = await subtle.importKey(
            'raw', // format
            naclKeyPair.publicKey, // The public key as a Uint8Array
            {
                name: "Ed25519"
            },
            true, // whether the key is extractable
            ["verify"] // allowed operations
        );
        console.log(jwk)

        const verify = await jwtVerify(jwt, publicKey)

        console.log(verify)
    })
});

const {assert} = require('chai');
const {utils} = require('@aeternity/aeproject');
const {generateMnemonic, mnemonicToSeed} = require('@aeternity/bip39');
const {
    getHdWalletAccountFromSeed,
    derivePathFromSeed,
    derivePathFromKey,
    getKeyPair,
    Encoding,
    encode
} = require("@aeternity/aepp-sdk");
const {SignJWT, jwtVerify, importPKCS8, importJWK, exportJWK} = require('jose')
const {subtle} = require('crypto').webcrypto;
const crypto = require('crypto');
const {encodeBase64} = require('tweetnacl-util');
const nacl = require('tweetnacl');
const asn1 = require('asn1.js');
const ecKeyUtils = require('eckey-utils');
const sdk = require("matrix-js-sdk")
const {encodeRecoveryKey} = require("matrix-js-sdk/lib/crypto/recoverykey");

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

    const generateMatrixBackup = async (secretKey) => {
        /*global.Olm = require('@matrix-org/olm');
        const client = sdk.createClient({ baseUrl: "http://localhost:8008", userId: "user_id", deviceId: "device_id" });
        await client.initCrypto();
        const key = await client.getCrypto()?.createRecoveryKeyFromPassphrase()
        */
        const recoveryKey = encodeRecoveryKey(secretKey.slice(0, 32))


        //const algorithm = Curve25519.init()
        //const [privateKey, authData] = await Curve25519.prepare(secretKey)
        //const recoveryKey = encodeRecoveryKey(secretKey);
        // 57yc aQSY eChx Kc3A KVTG Rh93 Xw6L MaUm cdD8 8yWc MRgN hA6W PkzF XD4J tdK6 KyoK P7kj kcgg YfbD NGT4 snNV SAjs bnbh
        // EsTH uZGN mafS LZL4 jBmQ XroT MdDr wp3S k4sg Qoj2 8q1v e1rZ

        console.log("recoveryKey", recoveryKey)
    }

    const signJWT = (payload, header,  exp, naclKeyPair) => {
        const base64url = require('base64url')

        const jwtBody = base64url.encode(JSON.stringify(header)) + '.' + base64url.encode(JSON.stringify({...payload, exp}))


        const jwtSignature = nacl.sign.detached(Buffer.from(jwtBody), Buffer.from(naclKeyPair.secretKey));


        const signedJwt = jwtBody + '.' + base64url.encode(Buffer.from(jwtSignature))

        return signedJwt
    }

    it('generate key', async () => {
        const mnemonic = generateMnemonic();
        const seed = mnemonicToSeed(mnemonic)

        const naclWalletKey = derivePathFromSeed('m/44h/457h', seed);
        const naclDerived = derivePathFromKey('12h/0h/0h', naclWalletKey);
        const naclKeyPair = getKeyPair(naclDerived.secretKey);


        const payload = {'user_id': '@test_7:shtest'}
        const header = {alg: 'EdDSA', typ: 'JWT'}
        const exp = new Date().getTime() + 30 * 60 * 1000

        console.log(signJWT(payload, header, exp, naclKeyPair));

        await generateMatrixBackup(naclKeyPair.secretKey);


        const aeKeyPair = {
            secretKey: Buffer.from(naclKeyPair.secretKey).toString('hex'),
            publicKey: encode(naclKeyPair.publicKey, Encoding.AccountAddress),
        };
        console.log(naclKeyPair, aeKeyPair)

        const jwk = {
            kty: "OKP",
            crv: "Ed25519",
            d: encodeBase64(naclKeyPair.secretKey.subarray(0, 32)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
            x: encodeBase64(naclKeyPair.publicKey).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
        };

        const jwt = await new SignJWT(payload)
            .setProtectedHeader(header)
            .setExpirationTime(exp)
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

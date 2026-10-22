import { injectable } from 'inversify';
/**
 * Converts Azure Key Vault ECDSA signatures into the canonical
 * secp256k1 signature format required by XRPL transactions.
 *
 * Azure Key Vault returns ES256K signatures as a raw 64-byte value:
 *
 *   [32-byte r][32-byte s]
 *
 * XRPL expects secp256k1 transaction signatures to be:
 *
 *   1. Canonicalized using low-S form
 *   2. DER encoded
 *
 * This service does NOT perform private-key signing.
 * Signing is performed inside Azure Key Vault.
 *
 * Its only responsibility is to convert the returned Azure signature
 * into the format that can be placed in the XRPL TxnSignature field.
 *
 * Flow:
 *
 * Azure Key Vault Sign
 *      ↓
 * raw r || s signature
 *      ↓
 * low-S normalization
 *      ↓
 * DER encoding
 *      ↓
 * XRPL TxnSignature
 */
@injectable()
export class XrplSignatureService {

    private static readonly SECP256K1_N =
        BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

    public toCanonicalDer(rawSignature: Buffer): string {

        if (rawSignature.length !== 64) {
            throw new Error('Expected 64-byte secp256k1 signature.');
        }

        const r = rawSignature.subarray(0, 32);
        const sRaw = rawSignature.subarray(32, 64);

        const sValue = BigInt(`0x${sRaw.toString('hex')}`);

        const halfN = XrplSignatureService.SECP256K1_N / BigInt(2);

        const canonicalS =
            sValue > halfN
                ? XrplSignatureService.SECP256K1_N - sValue
                : sValue;

        const sHex = canonicalS
            .toString(16)
            .padStart(64, '0');

        const s = Buffer.from(sHex, 'hex');

        const derR = this.encodeDerInteger(r);
        const derS = this.encodeDerInteger(s);

        const sequenceLength = derR.length + derS.length;

        const der = Buffer.concat([
            Buffer.from([0x30, sequenceLength]),
            derR,
            derS
        ]);

        return der.toString('hex').toUpperCase();
    }

    private encodeDerInteger(value: Buffer): Buffer {

        let bytes = Buffer.from(value);

        while (bytes.length > 1 && bytes[0] === 0x00) {
            bytes = bytes.subarray(1);
        }

        if ((bytes[0] & 0x80) !== 0) {
            bytes = Buffer.concat([
                Buffer.from([0x00]),
                bytes
            ]);
        }

        return Buffer.concat([
            Buffer.from([0x02, bytes.length]),
            bytes
        ]);
    }
}
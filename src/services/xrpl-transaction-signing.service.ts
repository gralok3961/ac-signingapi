import { createHash } from 'crypto';
import { injectable } from 'inversify';
import {
    encode,
    encodeForSigning,
    SubmittableTransaction
} from 'xrpl';

@injectable()
export class XrplTransactionSigningService {

    public prepareSigningPayload<T extends SubmittableTransaction>(
        transaction: T,
        publicKey: string
    ) {

        const transactionToSign = {
            ...transaction,
            SigningPubKey: publicKey
        };

        // XRPL-specific serialization used for single-signing.
        const signingHex = encodeForSigning(transactionToSign);

        // XRPL signing digest = first 256 bits of SHA-512 (SHA512Half).
        const digest = createHash('sha512')
            .update(Buffer.from(signingHex, 'hex'))
            .digest()
            .subarray(0, 32);

        return {
            transaction: transactionToSign,
            signingHex,
            digest
        };
    }

    public buildSignedBlob<T extends SubmittableTransaction>(
        transaction: T,
        signature: string
    ) {

        const signedTransaction = {
            ...transaction,
            TxnSignature: signature
        };

        const txBlob = encode(signedTransaction);

        return {
            transaction: signedTransaction,
            txBlob
        };
    }
}
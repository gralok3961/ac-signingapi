import { injectable } from 'inversify';
import { deriveAddress } from 'xrpl';

@injectable()
export class XrplKeyService {

    deriveFromCoordinates(
        publicKeyX: string,
        publicKeyY: string
    ) {
        const x = Buffer.from(publicKeyX, 'hex');
        const y = Buffer.from(publicKeyY, 'hex');

        if (x.length !== 32 || y.length !== 32) {
            throw new Error('Invalid secp256k1 public key coordinates.');
        }

        const isYEven = (y[y.length - 1] & 1) === 0;

        const prefix = isYEven ? '02' : '03';

        const compressedPublicKey =
            prefix + x.toString('hex').toUpperCase();

        const address = deriveAddress(compressedPublicKey);

        return {
            publicKey: compressedPublicKey,
            address
        };
    }
}
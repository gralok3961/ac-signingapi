import { SignAgentTransactionRequestDto, SignAgentTransactionResponseDto } from '../models/dtos/agent-transaction-signing';
import { inject, injectable } from 'inversify';
import { BlockChainId } from '@hashtrion/application/hash-protocol';
import { KeyVaultService } from '@services/key-vault.service';
import { XrplSignatureService } from '@services/xrpl-signature.service';
import { XrplTransactionSigningService } from '@services/xrpl-transaction-signing.service';
import { HttpError } from '../models/errors/http-error';
import { Payment, verifyKeypairSignature } from 'xrpl';

@injectable()
export class AgentTransactionSigningService {

    constructor(
        @inject(KeyVaultService) private readonly keyVaultService: KeyVaultService,
        @inject(XrplSignatureService) private readonly xrplSignatureService: XrplSignatureService,
        @inject(XrplTransactionSigningService) private readonly xrplTransactionSigningService: XrplTransactionSigningService
    ) { }

    public async sign(dto: SignAgentTransactionRequestDto): Promise<SignAgentTransactionResponseDto> {

        if (!dto || typeof dto !== 'object' || Array.isArray(dto)) {
            throw new HttpError(400, 'A signing request object is required.');
        }

        if (Object.keys(dto).some(key => key !== 'chainId' && key !== 'providerKeyReference' && key !== 'publicKey' && key !== 'transaction')) {
            throw new HttpError(400, 'Invalid signing request properties.');
        }

        if (!Number.isInteger(dto.chainId)) {
            throw new HttpError(400, 'chainId must be an integer.');
        }

        if (typeof dto.providerKeyReference !== 'string' || !dto.providerKeyReference.trim()) {
            throw new HttpError(400, 'providerKeyReference is required.');
        }

        if (typeof dto.publicKey !== 'string' || !/^(02|03)[0-9a-f]{64}$/i.test(dto.publicKey.trim())) {
            throw new HttpError(400, 'publicKey must be a valid compressed secp256k1 public key.');
        }

        if (!dto.transaction || typeof dto.transaction !== 'object' || Array.isArray(dto.transaction)) {
            throw new HttpError(400, 'transaction is required.');
        }

        switch (dto.chainId) {
            case BlockChainId.XRPL:
                return await this.signXrplTransaction(dto);
            default:
                throw new HttpError(400, 'Unsupported chainId.');
        }
    }

    private async signXrplTransaction(dto: SignAgentTransactionRequestDto): Promise<SignAgentTransactionResponseDto> {

        const transaction = dto.transaction as Payment;
        const providerKeyReference = dto.providerKeyReference.trim();
        const publicKey = dto.publicKey.trim().toUpperCase();

        if (transaction.TransactionType !== 'Payment') {
            throw new HttpError(400, 'Only XRPL Payment transactions are supported.');
        }

        if ('TxnSignature' in transaction) {
            throw new HttpError(400, 'Transaction must not already contain TxnSignature.');
        }

        if ('SigningPubKey' in transaction && transaction.SigningPubKey) {
            throw new HttpError(400, 'Transaction must not already contain SigningPubKey.');
        }

        const prepared = this.xrplTransactionSigningService.prepareSigningPayload(transaction, publicKey);

        const providerSignature = await this.keyVaultService.signDigest(providerKeyReference, prepared.digest);

        if (!providerSignature.verified) {
            throw new Error('Signing provider signature verification failed.');
        }

        const xrplSignature = this.xrplSignatureService.toCanonicalDer(Buffer.from(providerSignature.signature, 'hex'));

        const xrplVerified = verifyKeypairSignature(prepared.signingHex, xrplSignature, publicKey);

        if (!xrplVerified) {
            throw new Error('XRPL signature verification failed.');
        }

        const signed = this.xrplTransactionSigningService.buildSignedBlob(prepared.transaction, xrplSignature);

        return {
            payload: signed.txBlob
        };
    }
}
require('reflect-metadata');
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { Wallet, ECDSA, decode, encodeForSigning, verifyKeypairSignature } = require('xrpl');
const { AgentTransactionSigningService } = require('../src/services/agent-transaction-signing.service');
const { XrplSignatureService } = require('../src/services/xrpl-signature.service');
const { XrplTransactionSigningService } = require('../src/services/xrpl-transaction-signing.service');

// Ephemeral offline keys only; no Key Vault, network, or persisted wallet data.
function fixture() {
    const wallet = Wallet.generate(ECDSA.secp256k1);
    const transaction = {
        TransactionType: 'Payment', Account: wallet.classicAddress,
        Destination: 'rBgGZ9tc4him9KBzD8fKFiQz3fSZpaSwMH',
        Amount: '1000000', Fee: '12', Sequence: 1, LastLedgerSequence: 100
    };
    const signed = wallet.sign(transaction);
    const der = Buffer.from(decode(signed.tx_blob).TxnSignature, 'hex');
    const rLength = der[3];
    const sOffset = 4 + rLength;
    const r = der.subarray(4, sOffset);
    const s = der.subarray(sOffset + 2, sOffset + 2 + der[sOffset + 1]);
    const scalar = value => Buffer.from(value.toString('hex').slice(-64).padStart(64, '0'), 'hex');
    return {
        dto: { chainId: 1, providerKeyReference: 'https://offline-test.vault.azure.net/keys/agent/version', publicKey: wallet.publicKey, transaction },
        signature: Buffer.concat([scalar(r), scalar(s)]), signed
    };
}
function service(vault) {
    return new AgentTransactionSigningService(vault, new XrplSignatureService(), new XrplTransactionSigningService());
}

test('XRPL payment signing preserves the prepared transaction and verifies canonical signature', async () => {
    const { dto, signature, signed } = fixture();
    const original = structuredClone(dto);
    let calls = 0;
    const result = await service({ async signDigest(key, digest) {
        calls++;
        assert.equal(key, dto.providerKeyReference);
        assert.deepEqual(digest, new XrplTransactionSigningService().prepareSigningPayload(dto.transaction, dto.publicKey).digest);
        return { signature: signature.toString('hex'), verified: true };
    } }).sign(dto);
    assert.equal(calls, 1);
    assert.deepEqual(Object.keys(result), ['payload']);
    assert.equal(result.payload, signed.tx_blob);
    assert.deepEqual(dto, original);
    const decoded = decode(result.payload);
    const { TxnSignature, ...unsigned } = decoded;
    assert.equal(verifyKeypairSignature(encodeForSigning(unsigned), TxnSignature, dto.publicKey), true);
});

test('unsupported chains, non-payment transactions and already signed inputs never reach KMS', async () => {
    const { dto } = fixture();
    const signer = service({ async signDigest() { assert.fail('Unexpected KMS call'); } });
    for (const chainId of [2, 0, 999]) {
        await assert.rejects(signer.sign({ ...dto, chainId }), error => error.statusCode === 400 && error.message === 'Unsupported chainId.');
    }
    for (const transaction of [
        { ...dto.transaction, TransactionType: 'SetRegularKey' },
        { ...dto.transaction, TxnSignature: '' },
        { ...dto.transaction, SigningPubKey: dto.publicKey }
    ]) {
        await assert.rejects(signer.sign({ ...dto, transaction }), error => error.statusCode === 400);
    }
});

test('failed provider verification or mismatched signing key never returns a signed payload', async () => {
    const { dto, signature } = fixture();
    await assert.rejects(service({ async signDigest() {
        return { signature: signature.toString('hex'), verified: false };
    } }).sign(dto), /Signing provider signature verification failed/);
    await assert.rejects(service({ async signDigest() {
        return { signature: signature.toString('hex'), verified: true };
    } }).sign({ ...dto, publicKey: Wallet.generate(ECDSA.secp256k1).publicKey }), /XRPL signature verification failed/);
});

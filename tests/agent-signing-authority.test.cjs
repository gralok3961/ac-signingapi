require('reflect-metadata');
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { randomBytes } = require('node:crypto');
const { IncomingMessage, ServerResponse } = require('node:http');
const { Duplex } = require('node:stream');
const express = require('express');
const { InversifyExpressServer } = require('inversify-express-utils');
const { KeyVaultService } = require('../src/services/key-vault.service');
const { XrplKeyService } = require('../src/services/xrpl-key.service');
const { AgentSigningAuthorityService } = require('../src/services/agent-signing-authority.service');
const { HttpError } = require('../src/models/errors/http-error');
const { errorMiddleWare } = require('../src/middlewares/error.middleware');
const { HashCrossProtocol, BlockChainId } = require('../src/@hashtrion/application/hash-protocol');

const agentAccountId = '6ba7b810-9dad-41d1-80b4-00c04fd430c8';
const keyName = `hashtrion-agent-${agentAccountId}`;
const request = { agentAccountId, chainId: BlockChainId.XRPL };
// Public secp256k1 generator coordinates; no private key or credential is used.
const x = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const y = '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
function publicKey(name = keyName) {
    return {
        name,
        id: `https://offline-test.vault.azure.net/keys/${name}/0123456789abcdef0123456789abcdef`,
        keyType: 'EC',
        keyOperations: ['sign', 'verify'],
        key: { crv: 'P-256K', x: Buffer.from(x, 'hex'), y: Buffer.from(y, 'hex') },
        properties: { exportable: false, enabled: true }
    };
}
function azureError(statusCode, code) {
    return Object.assign(new Error('Synthetic internal provider diagnostic'), { statusCode, code });
}
function vaultWithClient(client) {
    // Exercise production methods while bypassing Azure credentials/client construction.
    const vault = Object.create(KeyVaultService.prototype);
    vault.client = client;
    vault.inFlightProvisioning = new Map();
    return vault;
}
function serviceFor(vault) {
    return new AgentSigningAuthorityService(vault, new XrplKeyService());
}
function expectedResponse(name = keyName) {
    return {
        provider: 1,
        providerKeyReference: publicKey(name).id,
        publicKey: `02${x.toUpperCase()}`,
        delegatedAuthorityIdentifier: 'rBgGZ9tc4him9KBzD8fKFiQz3fSZpaSwMH'
    };
}

// Drive the real Express/Inversify middleware chain entirely in memory, with no
// listener/socket connection, Azure requests, XRPL requests, or .env loading.
function dispatch(app, { method = 'POST', url = '/api/agent-signing-authority/provision', headers = {}, body = request, rawBody } = {}) {
    return new Promise((resolve, reject) => {
        const socket = new Duplex({ read() {}, write(_chunk, _encoding, done) { done(); } });
        const req = new IncomingMessage(socket);
        const res = new ServerResponse(req);
        const payload = rawBody ?? JSON.stringify(body);
        req.method = method;
        req.url = url;
        req.headers = { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(payload)), ...headers };
        res.end = function (chunk) {
            try {
                resolve({ status: res.statusCode, body: chunk ? JSON.parse(String(chunk)) : undefined });
            } catch (error) {
                reject(error);
            } finally {
                socket.destroy();
            }
            return this;
        };
        app.handle(req, res, error => {
            socket.destroy();
            if (error) reject(error);
            else resolve({ status: 404 });
        });
        req.push(payload);
        req.push(null);
    });
}

test('invalid identifiers, chains, or caller-selected key/digest fields never reach Key Vault', async () => {
    let calls = 0;
    const service = serviceFor({ getOrCreateSecp256k1Key() { calls++; throw new Error('Unexpected Key Vault call'); } });
    const invalid = [
        undefined, null, [], 'text', {},
        { chainId: 1 }, { agentAccountId },
        { ...request, agentAccountId: '' },
        { ...request, agentAccountId: 'not-a-uuid' },
        { ...request, agentAccountId: agentAccountId.replaceAll('-', '') },
        { ...request, agentAccountId: agentAccountId + String.fromCharCode(10) },
        { ...request, agentAccountId: agentAccountId + ' ' },
        { ...request, agentAccountId: 7 },
        { ...request, agentAccountId: '00000000-0000-0000-0000-000000000000' },
        { ...request, chainId: '1' }, { ...request, chainId: null },
        { ...request, chainId: 1.5 }, { ...request, chainId: NaN },
        { ...request, chainId: Infinity }, { ...request, chainId: 0 },
        { ...request, chainId: 999 },
        { ...request, chainId: 2 },
        { ...request, keyId: 'caller-selected' },
        { ...request, keyName: 'caller-selected' },
        { ...request, digest: 'caller-selected' }
    ];
    for (const dto of invalid) {
        await assert.rejects(service.provision(dto), error => error instanceof HttpError && error.statusCode === 400);
    }
    assert.equal(calls, 0);
    await assert.rejects(service.provision({ ...request, chainId: 2 }), /Unsupported chainId/);
});

test('retry and UUID case changes reuse the existing version and expose only public response fields', async () => {
    const keys = new Map();
    const reads = [];
    const creates = [];
    const vault = vaultWithClient({
        async getKey(name) {
            reads.push(name);
            if (!keys.has(name)) throw azureError(404, 'KeyNotFound');
            return keys.get(name);
        },
        async createEcKey(name, options) {
            creates.push(name);
            assert.deepEqual(options, { curve: 'P-256K', keyOps: ['sign', 'verify'], exportable: false });
            const key = publicKey(name);
            keys.set(name, key);
            return key;
        }
    });
    const service = serviceFor(vault);
    const first = await service.provision({ ...request, agentAccountId: agentAccountId.toUpperCase() });
    const retry = await service.provision(request);
    assert.deepEqual(first, expectedResponse());
    assert.deepEqual(retry, first);
    assert.deepEqual(reads, [keyName, keyName]);
    assert.deepEqual(creates, [keyName]);
    assert.match(keyName, /^[a-zA-Z0-9-]{1,127}$/);
});

test('only Azure key-not-found allows creation; other lookup and create failures propagate', async () => {
    for (const error of [
        azureError(403, 'Forbidden'), azureError(429, 'TooManyRequests'),
        azureError(500, 'ServerError'), azureError(404, 'VaultNotFound'),
        azureError(404, undefined), azureError(500, 'KeyNotFound'), new Error('Synthetic timeout')
    ]) {
        let creates = 0;
        const vault = vaultWithClient({
            async getKey() { throw error; },
            async createEcKey() { creates++; }
        });
        await assert.rejects(vault.getOrCreateSecp256k1Key(keyName), caught => caught === error);
        assert.equal(creates, 0);
    }
    const failure = azureError(403, 'Forbidden');
    let creates = 0;
    const vault = vaultWithClient({
        async getKey() { throw azureError(404, 'KeyNotFound'); },
        async createEcKey() { creates++; throw failure; }
    });
    await assert.rejects(vault.getOrCreateSecp256k1Key(keyName), caught => caught === failure);
    assert.equal(creates, 1);
});

test('incompatible, exportable, incomplete, or unversioned existing keys fail without replacement', async () => {
    const mutations = [
        key => { key.properties.exportable = true; },
        key => { delete key.properties.exportable; },
        key => { key.properties.enabled = false; },
        key => { key.keyType = 'RSA'; },
        key => { key.key.crv = 'P-256'; },
        key => { key.keyOperations = ['verify']; },
        key => { key.keyOperations.push('encrypt'); },
        key => { delete key.id; },
        key => { key.id = `https://offline-test.vault.azure.net/keys/${keyName}`; },
        key => { delete key.key.x; },
        key => { key.key.y = Buffer.alloc(31); }
    ];
    for (const mutate of mutations) {
        const key = publicKey();
        mutate(key);
        let creates = 0;
        const vault = vaultWithClient({
            async getKey() { return key; },
            async createEcKey() { creates++; }
        });
        await assert.rejects(serviceFor(vault).provision(request));
        assert.equal(creates, 0);
    }
});

test('registered production HTTP flow authenticates, sanitizes errors, and excludes debug routes', async t => {
    const previousKey = process.env.INTERNAL_API_KEY;
    t.after(() => {
        if (previousKey === undefined) delete process.env.INTERNAL_API_KEY;
        else process.env.INTERNAL_API_KEY = previousKey;
    });
    const internalKey = randomBytes(32).toString('hex');
    const authHeader = HashCrossProtocol.HttpHeader.hashApiKey;
    const headers = { [authHeader]: internalKey };
    let calls = 0;
    let lookupFailure;
    const vault = vaultWithClient({
        async getKey(name) {
            calls++;
            if (lookupFailure) throw lookupFailure;
            assert.equal(name, keyName);
            return publicKey();
        },
        async createEcKey() { assert.fail('Existing key must not be recreated'); }
    });
    // Load actual runtime DI and production controllers, never server.ts/TestController.
    const { container } = require('../src/@hashtrion/application/inversion-control/inversify.config');
    container.rebind(KeyVaultService).toConstantValue(vault);
    const server = new InversifyExpressServer(container);
    server.setConfig(app => app.use(express.json()));
    server.setErrorConfig(app => app.use(errorMiddleWare));
    const app = server.build();

    await t.test('missing or blank server config fails closed', async () => {
        for (const value of [undefined, '', '   ']) {
            if (value === undefined) delete process.env.INTERNAL_API_KEY;
            else process.env.INTERNAL_API_KEY = value;
            assert.deepEqual(await dispatch(app, { headers }), {
                status: 503, body: { message: 'Service unavailable', statusCode: 503 }
            });
        }
        assert.equal(calls, 0);
    });
    process.env.INTERNAL_API_KEY = internalKey;

    await t.test('missing, wrong, or differently sized keys return 401 before provisioning', async () => {
        for (const supplied of [undefined, '', 'wrong', `${internalKey}extra`, internalKey.slice(1)]) {
            const candidate = supplied === undefined ? {} : { [authHeader]: supplied };
            assert.deepEqual(await dispatch(app, { headers: candidate }), {
                status: 401, body: { message: 'Unauthorized', statusCode: 401 }
            });
        }
        assert.equal(calls, 0);
    });

    await t.test('signing endpoint remains registered and protected without invoking KMS', async () => {
        const url = '/api/agent-transaction-signing/sign';
        assert.equal((await dispatch(app, { url })).status, 401);
        const response = await dispatch(app, { url, headers, body: {} });
        assert.equal(response.status, 400);
        assert.equal(response.body.message, 'chainId must be an integer.');
    });

    await t.test('valid auth returns only the public signing-authority DTO', async () => {
        assert.deepEqual(await dispatch(app, { headers }), { status: 200, body: expectedResponse() });
        assert.equal(calls, 1);
    });

    await t.test('validation and JSON failures are safe 400 responses without Azure access', async () => {
        const before = calls;
        for (const body of [null, { ...request, agentAccountId: 'invalid' }, { ...request, chainId: 2 }]) {
            const response = await dispatch(app, { headers, body });
            assert.equal(response.status, 400);
            assert.equal(response.body.statusCode, 400);
        }
        assert.deepEqual(await dispatch(app, { headers, rawBody: '{"sensitive_input":' }), {
            status: 400, body: { message: 'Invalid JSON request body', statusCode: 400 }
        });
        assert.equal(calls, before);
    });

    await t.test('provider errors do not disclose SDK diagnostics', async () => {
        lookupFailure = azureError(403, 'Forbidden');
        assert.deepEqual(await dispatch(app, { headers }), {
            status: 500, body: { message: 'Server Error', statusCode: 500 }
        });
        lookupFailure = undefined;
    });

    await t.test('all retained debug endpoints are absent from runtime', async () => {
        const before = calls;
        for (const [method, path] of [
            ['GET', '/keyvault'], ['POST', '/agent-account'], ['POST', '/keyvault/sign'],
            ['GET', '/xrpl/account'], ['POST', '/xrpl/payment/autofill'],
            ['POST', '/xrpl/payment/signing-payload'], ['POST', '/xrpl/payment/sign']
        ]) {
            assert.equal((await dispatch(app, { method, url: `/api/test${path}`, headers })).status, 404);
        }
        assert.equal(calls, before);
        assert.deepEqual(await dispatch(app, { method: 'GET', url: '/health' }), {
            status: 404
        });
    });
});


function deferred() {
    let resolve;
    let reject;
    const promise = new Promise((resolvePromise, rejectPromise) => {
        resolve = resolvePromise;
        reject = rejectPromise;
    });
    return { promise, resolve, reject };
}

test('same-key first-time calls share one lookup/create flight, including arrivals during creation', async () => {
    const lookup = deferred();
    const creation = deferred();
    const creationStarted = deferred();
    let reads = 0;
    let creates = 0;
    const vault = vaultWithClient({
        getKey(name) {
            assert.equal(name, 'same-key');
            reads++;
            return lookup.promise;
        },
        createEcKey(name, options) {
            assert.equal(name, 'same-key');
            assert.deepEqual(options, { curve: 'P-256K', keyOps: ['sign', 'verify'], exportable: false });
            creates++;
            creationStarted.resolve();
            return creation.promise;
        }
    });
    const callers = Array.from({ length: 8 }, () => vault.getOrCreateSecp256k1Key('same-key'));
    assert.equal(reads, 1);
    assert.equal(creates, 0);
    for (const caller of callers) assert.strictEqual(caller, callers[0]);

    lookup.reject(azureError(404, 'KeyNotFound'));
    await creationStarted.promise;
    callers.push(vault.getOrCreateSecp256k1Key('same-key'));
    assert.strictEqual(callers.at(-1), callers[0]);
    assert.equal(reads, 1);
    assert.equal(creates, 1);

    creation.resolve(publicKey('same-key'));
    const results = await Promise.all(callers);
    for (const result of results) assert.strictEqual(result, results[0]);
    assert.deepEqual(results[0], {
        name: 'same-key', id: publicKey('same-key').id, keyType: 'EC', curve: 'P-256K',
        publicKeyX: x, publicKeyY: y, exportable: false
    });
    assert.equal(vault.inFlightProvisioning.size, 0);
});

test('different key names run independently while same-key callers still coalesce', async () => {
    const lookups = new Map([['key-A', deferred()], ['key-B', deferred()]]);
    const reads = [];
    const creates = [];
    const vault = vaultWithClient({
        getKey(name) {
            reads.push(name);
            return lookups.get(name).promise;
        },
        async createEcKey(name) {
            creates.push(name);
            return publicKey(name);
        }
    });
    const a = vault.getOrCreateSecp256k1Key('key-A');
    const b = vault.getOrCreateSecp256k1Key('key-B');
    assert.strictEqual(vault.getOrCreateSecp256k1Key('key-A'), a);
    assert.strictEqual(vault.getOrCreateSecp256k1Key('key-B'), b);
    assert.notStrictEqual(a, b);
    assert.deepEqual(reads, ['key-A', 'key-B']);

    // B must be able to finish while A's lookup is still pending.
    lookups.get('key-B').reject(azureError(404, 'KeyNotFound'));
    const resultB = await b;
    assert.equal(resultB.id, publicKey('key-B').id);
    assert.deepEqual(creates, ['key-B']);
    assert.equal(vault.inFlightProvisioning.has('key-A'), true);
    assert.equal(vault.inFlightProvisioning.has('key-B'), false);

    lookups.get('key-A').reject(azureError(404, 'KeyNotFound'));
    const resultA = await a;
    assert.equal(resultA.id, publicKey('key-A').id);
    assert.deepEqual(creates, ['key-B', 'key-A']);
    assert.equal(vault.inFlightProvisioning.size, 0);
});

for (const stage of ['lookup', 'creation', 'validation']) {
    test(`${stage} failure is shared, cleared, and followed by a fresh successful same-key lookup`, async () => {
        const pending = deferred();
        const creationStarted = deferred();
        const failure = azureError(403, 'Forbidden');
        let reads = 0;
        let creates = 0;
        const vault = vaultWithClient({
            getKey() {
                reads++;
                if (reads > 1) return Promise.resolve(publicKey());
                if (stage === 'creation') return Promise.reject(azureError(404, 'KeyNotFound'));
                return pending.promise;
            },
            createEcKey() {
                creates++;
                creationStarted.resolve();
                return pending.promise;
            }
        });
        const callers = Array.from({ length: 5 }, () => vault.getOrCreateSecp256k1Key(keyName));
        const settled = Promise.allSettled(callers);
        if (stage === 'creation') await creationStarted.promise;
        if (stage === 'validation') {
            const invalidKey = publicKey();
            invalidKey.properties.exportable = true;
            pending.resolve(invalidKey);
        } else {
            pending.reject(failure);
        }

        const results = await settled;
        for (const result of results) {
            assert.equal(result.status, 'rejected');
            assert.strictEqual(result.reason, results[0].reason);
            if (stage !== 'validation') assert.strictEqual(result.reason, failure);
        }
        assert.equal(reads, 1);
        assert.equal(creates, stage === 'creation' ? 1 : 0);
        assert.equal(vault.inFlightProvisioning.size, 0);

        const retry = await vault.getOrCreateSecp256k1Key(keyName);
        assert.equal(retry.id, publicKey().id);
        assert.equal(reads, 2);
        assert.equal(creates, stage === 'creation' ? 1 : 0);
        assert.equal(vault.inFlightProvisioning.size, 0);
    });
}

test('existing keys share one lookup and completed flights are not cached', async () => {
    const lookup = deferred();
    let reads = 0;
    let creates = 0;
    let currentKey = publicKey();
    const vault = vaultWithClient({
        getKey() {
            reads++;
            return reads === 1 ? lookup.promise : Promise.resolve(currentKey);
        },
        createEcKey() { creates++; assert.fail('Existing keys must never be recreated'); }
    });
    const callers = Array.from({ length: 5 }, () => vault.getOrCreateSecp256k1Key(keyName));
    assert.equal(reads, 1);
    lookup.resolve(currentKey);
    const results = await Promise.all(callers);
    for (const result of results) assert.strictEqual(result, results[0]);
    assert.deepEqual(results[0], {
        name: keyName, id: currentKey.id, keyType: 'EC', curve: 'P-256K',
        publicKeyX: x, publicKeyY: y, exportable: false
    });
    assert.equal(vault.inFlightProvisioning.size, 0);

    // Simulate a later provider response to prove no completed result is retained.
    currentKey = { ...publicKey(), id: publicKey().id.replace(/[^/]+$/, 'fedcba9876543210fedcba9876543210') };
    const subsequent = await vault.getOrCreateSecp256k1Key(keyName);
    assert.equal(subsequent.id, currentKey.id);
    assert.notEqual(subsequent.id, results[0].id);
    assert.equal(reads, 2);
    assert.equal(creates, 0);
    assert.equal(vault.inFlightProvisioning.size, 0);
});

test('completion of an older flight cannot remove a replacement entry', async () => {
    const lookup = deferred();
    const replacement = deferred();
    const vault = vaultWithClient({ getKey() { return lookup.promise; } });
    const original = vault.getOrCreateSecp256k1Key(keyName);
    // Exercise the identity guard without starting any additional Azure operation.
    vault.inFlightProvisioning.set(keyName, replacement.promise);
    lookup.resolve(publicKey());
    const result = await original;
    assert.strictEqual(vault.inFlightProvisioning.get(keyName), replacement.promise);
    assert.strictEqual(vault.getOrCreateSecp256k1Key(keyName), replacement.promise);
    replacement.resolve(result);
    vault.inFlightProvisioning.delete(keyName);
});

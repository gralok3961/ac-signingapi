# Hashtrion Signing API — XRPL Agentic Payments

## Overview

This internal service provisions Agent signing authorities and signs prepared XRPL Payment transactions for Hashtrion Agentic Commerce. Private-key operations are performed by Azure Key Vault; the service returns public authority information or a signed transaction blob.

The Wallet signs `SetRegularKey` locally. This API neither submits that transaction nor activates the authority on the ledger.

## Key Features

- Provisioning of non-exportable, software-protected secp256k1 (EC, P-256K) signing keys in Azure Key Vault.
- Reuse of an existing compatible key under a deterministic Agent account key name.
- Public-key compression and derivation of the delegated XRPL authority address.
- XRPL single-signing serialization and SHA512Half digest preparation.
- Azure ES256K signing and verification, followed by low-S DER conversion and XRPL signature verification.
- Internal API authentication and sanitized HTTP errors.

## How It Works

1. Platform API calls `POST /api/agent-signing-authority/provision` with `agentAccountId` and `chainId`.
2. The service retrieves or creates `hashtrion-agent-{agentAccountId}` and validates its key properties. It returns `provider`, a versioned `providerKeyReference`, `publicKey`, and `delegatedAuthorityIdentifier`.
3. The Wallet signs SetRegularKey locally. The Transaction API submits the transaction to XRPL and verifies the activated RegularKey. Provisioning alone does not activate it.
4. Transaction API calls `POST /api/agent-transaction-signing/sign` with `chainId`, `providerKeyReference`, `publicKey`, and a prepared `transaction`.
5. The service prepares the signing digest, requests Key Vault signing, verifies the provider result, normalizes the signature, and verifies it against the supplied XRPL public key.
6. The response contains `payload`, the signed transaction blob. Transaction API validates the returned transaction and handles XRPL submission.

Both endpoints support `chainId: 1` only. Unsupported chain IDs are rejected with HTTP 400.

## Authentication & Security

Both controllers require `x-hashtrion-internal-key`, matched against `INTERNAL_API_KEY` using a timing-safe comparison of fixed-size hashes. Missing server configuration fails closed; missing or invalid caller credentials are rejected.

Provisioning accepts only an Agent account UUID and chain ID. Existing keys must be enabled, non-exportable secp256k1 keys with sign/verify operations and a versioned reference. Only a Key Vault `KeyNotFound` response permits creation. Concurrent provisioning for the same name is coordinated within one Node process.

Signing accepts XRPL `Payment` transactions only and rejects inputs that already contain a transaction signature or a nonempty signing public key. It verifies both the provider result and the final XRPL signature before returning a blob. Unexpected errors return a generic response rather than provider diagnostics.

The service uses `DefaultAzureCredential` and does not export private keys. Key Vault access permissions must be configured externally. Signing uses the caller-supplied key reference; this service does not independently enforce Spending Policy, validate checkout authorization, or verify the account's on-ledger RegularKey relationship. Those checks belong to the existing Platform and Transaction API flow.

## Project Structure

| Directory / file | Responsibility |
| --- | --- |
| `src/controllers/` | Internal provisioning and payment-signing endpoints |
| `src/services/` | Key Vault operations, authority derivation, serialization, and signature verification |
| `src/models/` | Request/response DTOs and HTTP errors |
| `src/middlewares/` | Internal API authentication and error handling |
| `src/@hashtrion/application/` | Shared protocol identifiers, configuration, and dependency registration |
| `src/server.ts`, `src/shutdown.ts` | HTTP startup and graceful shutdown |
| `tests/` | Offline provisioning, authentication, and XRPL signing regression tests |

## Build and Configuration

Use Node.js 24, matching the Azure build pipeline, and npm. The package declares Node.js 20 or later.

```bash
npm ci
npm run build
npm start
```

For local development, use `npm run dev`. The server loads `.env` through dotenv; keep local credentials out of Git. In Azure, supply configuration through App Settings and the approved identity setup.

| Setting | Purpose |
| --- | --- |
| `PORT` | HTTP port; defaults to `9003` |
| `AZURE_KEY_VAULT_NAME` | Vault containing Agent signing authority keys |
| `INTERNAL_API_KEY` | Shared internal credential matching authorized callers |
| Azure identity configuration | Credentials supported by `DefaultAzureCredential`, such as managed identity or local Azure CLI authentication |

No XRPL node URL is required: this API serializes and signs transactions without connecting to the ledger. Provisioning requires Key Vault key lookup/create access; signing requires sign/verify access. Do not place secrets in source or documentation.

Run the offline tests after installing development dependencies:

```bash
node -r ts-node/register -r tsconfig-paths/register --test tests/*.test.cjs
```

Tests use in-memory request handling, mocked provider operations, and ephemeral local signing keys. They do not create Azure keys or submit blockchain transactions.


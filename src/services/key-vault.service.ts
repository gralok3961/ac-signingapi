import { injectable } from 'inversify';
import { DefaultAzureCredential } from '@azure/identity';
import { CryptographyClient, KeyClient, KeyVaultKey, parseKeyVaultKeyIdentifier } from '@azure/keyvault-keys';

type Secp256k1PublicKeyInfo = Awaited<ReturnType<KeyVaultService['createSecp256k1Key']>>;

@injectable()
export class KeyVaultService {
  private readonly credential: DefaultAzureCredential;
  private readonly client: KeyClient;
  // This service is a singleton; coordination is local to the current Node process.
  private readonly inFlightProvisioning = new Map<string, Promise<Secp256k1PublicKeyInfo>>();

  constructor() {
    const keyVaultName = process.env.AZURE_KEY_VAULT_NAME;

    if (!keyVaultName) {
      throw new Error('AZURE_KEY_VAULT_NAME is not configured.');
    }

    this.credential = new DefaultAzureCredential();

    this.client = new KeyClient(`https://${keyVaultName}.vault.azure.net`, this.credential);
  }

  getOrCreateSecp256k1Key(keyName: string): Promise<Secp256k1PublicKeyInfo> {
    const existingPromise = this.inFlightProvisioning.get(keyName);
    if (existingPromise) {
      return existingPromise;
    }

    const provisioningPromise = this.getOrCreateSecp256k1KeyInternal(keyName).finally(() => {
      if (this.inFlightProvisioning.get(keyName) === provisioningPromise) {
        this.inFlightProvisioning.delete(keyName);
      }
    });

    this.inFlightProvisioning.set(keyName, provisioningPromise);
    return provisioningPromise;
  }

  private async getOrCreateSecp256k1KeyInternal(keyName: string) {

    let key: KeyVaultKey;
    try {

      key = await this.client.getKey(keyName);
      
    } catch (error: unknown) {
      // A missing key is the only lookup failure that permits creation.
      if (typeof error === 'object' && error !== null &&
          'statusCode' in error && error.statusCode === 404 &&
          'code' in error && error.code === 'KeyNotFound') {
        return this.createSecp256k1Key(keyName);
      }
      throw error;
    }
    return this.toPublicKeyInfo(key);
  }

  async createSecp256k1Key(keyName: string) {

    const key = await this.client.createEcKey(keyName, {
      curve: 'P-256K',
      keyOps: ['sign', 'verify'],
      exportable: false
    });

    return this.toPublicKeyInfo(key);
  }

  private toPublicKeyInfo(key: KeyVaultKey) {
    if (!key.id || !parseKeyVaultKeyIdentifier(key.id).version) {
      throw new Error('Key Vault did not return a versioned key reference.');
    }
    if ((key.keyType !== 'EC' && key.keyType !== 'EC-HSM') ||
        key.key?.crv !== 'P-256K' || key.properties.exportable !== false ||
        key.properties.enabled === false ||
        !key.keyOperations?.includes('sign') || !key.keyOperations.includes('verify') ||
        key.keyOperations.some(operation => operation !== 'sign' && operation !== 'verify')) {
      throw new Error('Key Vault key is not a usable non-exportable secp256k1 signing authority.');
    }

    return {
      name: key.name,
      id: key.id,
      keyType: key.keyType,
      curve: key.key?.crv,

      publicKeyX: key.key?.x
        ? Buffer.from(key.key.x).toString('hex')
        : undefined,

      publicKeyY: key.key?.y
        ? Buffer.from(key.key.y).toString('hex')
        : undefined,

      exportable: key.properties.exportable
    };
  }

  async signDigest(keyId: string, digest: Buffer) {

    if (digest.length !== 32) {
      throw new Error('ES256K digest must be 32 bytes.');
    }
    
    const cryptoClient = new CryptographyClient(keyId, this.credential);

    const signResult = await cryptoClient.sign('ES256K', digest);

    const verifyResult = await cryptoClient.verify('ES256K', digest, signResult.result);

    return {
      signature: Buffer.from(signResult.result).toString('hex').toUpperCase(),

      verified: verifyResult.result
    };
  }
}
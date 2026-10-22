import { inject, injectable } from 'inversify';
import { AgentSigningProvider, BlockChainId } from '@hashtrion/application/hash-protocol';
import { KeyVaultService } from '@services/key-vault.service';
import { XrplKeyService } from '@services/xrpl-key.service';
import {
    ProvisionAgentSigningAuthorityRequestDto,
    ProvisionAgentSigningAuthorityResponseDto
} from '../models/dtos/agent-signing-authority';
import { HttpError } from '../models/errors/http-error';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

@injectable()
export class AgentSigningAuthorityService {
    constructor(
        @inject(KeyVaultService) private readonly keyVaultService: KeyVaultService,
        @inject(XrplKeyService) private readonly xrplKeyService: XrplKeyService
    ) { }

    public async provision(
        dto: ProvisionAgentSigningAuthorityRequestDto
    ): Promise<ProvisionAgentSigningAuthorityResponseDto> {
        if (!dto || typeof dto !== 'object' || Array.isArray(dto)) {
            throw new HttpError(400, 'A provisioning request object is required.');
        }
        if (Object.keys(dto).some(key => key !== 'agentAccountId' && key !== 'chainId')) {
            throw new HttpError(400, 'Only agentAccountId and chainId are accepted.');
        }
        if (typeof dto.agentAccountId !== 'string' || dto.agentAccountId.length !== 36 ||
            !UUID_PATTERN.test(dto.agentAccountId)) {
            throw new HttpError(400, 'agentAccountId must be a valid UUID.');
        }
        if (!Number.isInteger(dto.chainId)) {
            throw new HttpError(400, 'chainId must be an integer.');
        }

        switch (dto.chainId) {
            case BlockChainId.XRPL:
                return this.provisionXrplAuthority(dto.agentAccountId.toLowerCase());
            default:
                throw new HttpError(400, 'Unsupported chainId.');
        }
    }

    private async provisionXrplAuthority(
        agentAccountId: string
    ): Promise<ProvisionAgentSigningAuthorityResponseDto> {
        // This is the future RegularKey authority (rKMS), never the Wallet's rAGENT.
        const keyName = `hashtrion-agent-${agentAccountId}`;
        const key = await this.keyVaultService.getOrCreateSecp256k1Key(keyName);

        if (!key.id || !key.publicKeyX || !key.publicKeyY) {
            throw new Error('Key Vault did not return signing authority public information.');
        }

        const xrplIdentity = this.xrplKeyService.deriveFromCoordinates(
            key.publicKeyX,
            key.publicKeyY
        );

        return {
            provider: AgentSigningProvider.AzureKeyVault,
            providerKeyReference: key.id,
            publicKey: xrplIdentity.publicKey,
            delegatedAuthorityIdentifier: xrplIdentity.address
        };
    }
}

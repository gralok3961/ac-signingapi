import { AgentSigningProvider } from "@hashtrion/application/hash-protocol";

export interface ProvisionAgentSigningAuthorityRequestDto {
    agentAccountId: string;
    chainId: number;
}
export interface ProvisionAgentSigningAuthorityResponseDto {
    provider: AgentSigningProvider;
    providerKeyReference: string;
    publicKey: string;
    delegatedAuthorityIdentifier: string;
}

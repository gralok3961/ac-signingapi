export const HashCrossProtocol = {
    HttpHeader: {
        hashApiKey: "x-hashtrion-internal-key"
    }
} as const;

export enum BlockChainId {
    XRPL = 1
}

export enum AgentSigningProvider {
    AzureKeyVault = 1
}

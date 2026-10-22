export interface SignAgentTransactionRequestDto {
    chainId: number;
    providerKeyReference: string;
    publicKey: string;
    transaction: unknown;
}
export interface SignAgentTransactionResponseDto {
    payload: string;
}
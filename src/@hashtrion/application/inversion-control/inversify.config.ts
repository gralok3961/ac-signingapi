import { Container } from 'inversify';
import { XrplKeyService } from '@services/xrpl-key.service';
import { AgentSigningAuthorityService } from '@services/agent-signing-authority.service';
import { XrplSignatureService } from '@services/xrpl-signature.service';
import { AgentSigningAuthorityController } from '@controllers/agent-signing-authority.controller';
import { KeyVaultService } from '@services/key-vault.service';
import { XrplTransactionSigningService } from '@services/xrpl-transaction-signing.service';
import { AgentTransactionSigningService } from '@services/agent-transaction-signing.service';
import { AgentTransactionSigningController } from '@controllers/agent-transaction-signing.controller';

export const container = new Container();

// controllers
container.bind<AgentSigningAuthorityController>(AgentSigningAuthorityController).toSelf().inRequestScope();
container.bind<AgentTransactionSigningController>(AgentTransactionSigningController).toSelf().inRequestScope();

// services
container.bind<KeyVaultService>(KeyVaultService).toSelf().inSingletonScope();
container.bind<XrplKeyService>(XrplKeyService).toSelf().inSingletonScope();
container.bind<XrplSignatureService>(XrplSignatureService).toSelf().inSingletonScope();
container.bind<XrplTransactionSigningService>(XrplTransactionSigningService).toSelf().inSingletonScope();

container.bind<AgentSigningAuthorityService>(AgentSigningAuthorityService).toSelf().inSingletonScope();
container.bind<AgentTransactionSigningService>(AgentTransactionSigningService).toSelf().inSingletonScope();

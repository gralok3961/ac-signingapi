import { Request, Response } from 'express';
import { inject } from 'inversify';
import { controller, httpPost } from 'inversify-express-utils';
import { internalApiAuth } from '@middlewares/internal-api-auth.middleware';
import { AgentTransactionSigningService } from '@services/agent-transaction-signing.service';

@controller('/api/agent-transaction-signing', internalApiAuth)
export class AgentTransactionSigningController {

    constructor(@inject(AgentTransactionSigningService) private readonly agentTransactionSigningService: AgentTransactionSigningService) { }

    @httpPost('/sign')
    public async sign(req: Request, res: Response): Promise<Response> {

        const result = await this.agentTransactionSigningService.sign(req.body);

        return res.json(result);
    }
}
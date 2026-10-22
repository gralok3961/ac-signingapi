import { Request, Response } from 'express';
import { inject } from 'inversify';
import { controller, httpPost } from 'inversify-express-utils';
import { internalApiAuth } from '@middlewares/internal-api-auth.middleware';
import { AgentSigningAuthorityService } from '@services/agent-signing-authority.service';

@controller('/api/agent-signing-authority', internalApiAuth)
export class AgentSigningAuthorityController {
    constructor(
        @inject(AgentSigningAuthorityService)
        private readonly agentSigningAuthorityService: AgentSigningAuthorityService
    ) { }

    @httpPost('/provision')
    public async provision(req: Request, res: Response): Promise<Response> {

        const result = await this.agentSigningAuthorityService.provision(req.body);
        
        return res.json(result);
    }
}

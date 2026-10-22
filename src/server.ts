import 'dotenv/config';
import 'reflect-metadata';
import express from 'express';
import { InversifyExpressServer } from 'inversify-express-utils';

import { config } from './@hashtrion/application/config/config.init';
import { container } from './@hashtrion/application/inversion-control/inversify.config';
import { errorMiddleWare } from '@middlewares/error.middleware';
import { registerGracefulShutdown } from './shutdown';

const server = new InversifyExpressServer(container);

server.setConfig((app) => {

    app.disable('x-powered-by');
    app.use(express.json());

    app.get('/', (_req, res) => {
        res.send('Hashtrion Signing API');
    });
});

server.setErrorConfig((app) => {
    app.use(errorMiddleWare);
});

const httpServer = server.build().listen(config.port, () => {
    console.log(
        `${config.serviceName} listening on port ${config.port}`
    );
});

httpServer.on('error', (error: NodeJS.ErrnoException) => {

    console.error(
        `HTTP server failed: ${error.code ?? 'UNKNOWN'}`
    );

    process.exitCode = 1;
});

// Gracefully close HTTP connections
registerGracefulShutdown(httpServer);
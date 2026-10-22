import { Server } from 'http';

export function registerGracefulShutdown(
    server: Server
): void {

    let shuttingDown = false;

    const shutdown = async (signal: string) => {

        if (shuttingDown) return;

        shuttingDown = true;

        console.log(`\nReceived ${signal}. Shutting down gracefully...`);

        try {

            // Stop accepting new HTTP connections
            await new Promise<void>((resolve) => {
                server.close(() => {
                    console.log('HTTP server closed.');
                    resolve();
                });
            });

        } catch (error) {

            console.error('Error during shutdown:', error);

        } finally {

            process.exit(0);
        }
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
}
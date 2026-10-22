const port = Number(process.env.PORT ?? 9003);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('PORT must be an integer between 1 and 65535.');
}

export const config = Object.freeze({
  serviceName: 'hashtrion.signing.api',
  port,
});

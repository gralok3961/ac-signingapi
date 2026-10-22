// Only explicitly safe application messages may be sent to callers.
export class HttpError extends Error {
    constructor(
        public readonly statusCode: 400 | 401 | 503,
        message: string
    ) {
        super(message);
        this.name = 'HttpError';
    }
}

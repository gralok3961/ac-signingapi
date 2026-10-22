import { NextFunction, Request, Response } from 'express';
import { HttpError } from '../models/errors/http-error';

export function errorMiddleWare(
    err: unknown,
    _req: Request,
    res: Response,
    next: NextFunction
) {
    if (res.headersSent) {
        return next(err);
    }

    if (err instanceof HttpError) {
        return res.status(err.statusCode).json({
            message: err.message,
            statusCode: err.statusCode
        });
    }

    // Express JSON parse errors can contain the submitted body; never echo it.
    if (err instanceof SyntaxError && 'type' in err && err.type === 'entity.parse.failed') {
        return res.status(400).json({
            message: 'Invalid JSON request body',
            statusCode: 400
        });
    }

    return res.status(500).json({
        message: 'Server Error',
        statusCode: 500
    });
}

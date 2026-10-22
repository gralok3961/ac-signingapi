import { createHash, timingSafeEqual } from 'crypto';
import { NextFunction, Request, Response } from 'express';
import { HashCrossProtocol } from '@hashtrion/application/hash-protocol';
import { HttpError } from '../models/errors/http-error';

export function internalApiAuth(req: Request, _res: Response, next: NextFunction): void {
    const expectedKey = process.env.INTERNAL_API_KEY;

    if (!expectedKey || expectedKey.trim().length === 0) {
        next(new HttpError(503, 'Service unavailable'));
        return;
    }

    const suppliedKey = req.get(HashCrossProtocol.HttpHeader.hashApiKey);
    if (!suppliedKey) {
        next(new HttpError(401, 'Unauthorized'));
        return;
    }

    // Fixed-size hashes allow a timing-safe comparison even for different lengths.
    const expectedHash = createHash('sha256').update(expectedKey).digest();
    const suppliedHash = createHash('sha256').update(suppliedKey).digest();
    if (!timingSafeEqual(expectedHash, suppliedHash)) {
        next(new HttpError(401, 'Unauthorized'));
        return;
    }

    next();
}

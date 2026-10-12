import { createHash, timingSafeEqual } from 'node:crypto'
import type { NextFunction, Request, RequestHandler, Response } from 'express'

type RequireBearerTokenOptions = {
    /** The exact token clients must send as `Authorization: Bearer <token>`. */
    token: string
}

/**
 * Constant-time comparison of two secrets. Both sides are hashed first so
 * `timingSafeEqual` always sees equal lengths, which also avoids leaking the
 * configured token's length through early-exit comparisons.
 */
function tokensMatch(candidate: string, expected: string): boolean {
    const candidateDigest = createHash('sha256').update(candidate).digest()
    const expectedDigest = createHash('sha256').update(expected).digest()
    return timingSafeEqual(candidateDigest, expectedDigest)
}

function unauthorized(res: Response): void {
    res.status(401).set('WWW-Authenticate', 'Bearer').json({
        error: 'invalid_token',
        error_description: 'A valid Authorization: Bearer token is required',
    })
}

/**
 * Express middleware that rejects requests unless they carry the configured
 * bearer token in the `Authorization` header.
 *
 * Without it, a publicly exposed HTTP server lets anyone who knows the URL
 * run MCP tools with the operator's `TODOIST_API_KEY`. Set `MCP_BEARER_TOKEN`
 * (see `src/main-http.ts`) to enable.
 *
 * - Missing `Authorization` header → 401.
 * - Non-Bearer scheme or wrong token → 401.
 *
 * `/health` is a separate route and stays unguarded so deployment probes keep
 * working.
 */
function requireBearerToken(options: RequireBearerTokenOptions): RequestHandler {
    return (req: Request, res: Response, next: NextFunction): void => {
        const header = req.headers.authorization
        const separatorIndex = header?.indexOf(' ') ?? -1
        // The auth scheme is case-insensitive per RFC 7235; the token is not.
        const scheme = separatorIndex === -1 ? header : header?.slice(0, separatorIndex)
        const candidate =
            separatorIndex === -1 ? '' : (header?.slice(separatorIndex + 1) ?? '').trim()
        if (
            scheme?.toLowerCase() !== 'bearer' ||
            candidate === '' ||
            !tokensMatch(candidate, options.token)
        ) {
            unauthorized(res)
            return
        }
        next()
    }
}

export { requireBearerToken, type RequireBearerTokenOptions }

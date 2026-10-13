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
 * - Wrong scheme, wrong token, or empty token → 401.
 * - `Bearer <token>` (scheme case-insensitive per RFC 7235) → accepted.
 * - `<token>` without any scheme → accepted too. Some hosted clients (Mistral's
 *   production connector runner) send the bare token; the timing-safe token
 *   match is the security boundary, not the scheme spelling.
 *
 * `/health` is a separate route and stays unguarded so deployment probes keep
 * working.
 */
function requireBearerToken(options: RequireBearerTokenOptions): RequestHandler {
    return (req: Request, res: Response, next: NextFunction): void => {
        const header = req.headers.authorization
        const separatorIndex = header?.indexOf(' ') ?? -1
        const scheme = separatorIndex === -1 ? undefined : header?.slice(0, separatorIndex)
        const candidate =
            separatorIndex === -1
                ? (header ?? '').trim()
                : (header?.slice(separatorIndex + 1) ?? '').trim()
        const schemeValid = scheme === undefined || scheme.toLowerCase() === 'bearer'
        if (schemeValid && candidate !== '' && tokensMatch(candidate, options.token)) {
            next()
            return
        }
        unauthorized(res)
    }
}

export { requireBearerToken, type RequireBearerTokenOptions }

import { createHash } from 'node:crypto'
import type { NextFunction, Request, RequestHandler, Response } from 'express'

/**
 * Fingerprint an Authorization header for logs: enough to compare the
 * credential a client actually sent against the one from another client
 * (e.g. Mistral's debugger vs. its production runner), without the token
 * ever appearing in logs.
 */
function authFingerprint(authorization: string | undefined): string {
    if (!authorization) {
        return 'none'
    }
    return createHash('sha256').update(authorization).digest('hex').slice(0, 12)
}

/**
 * Express middleware that logs one line per request to stdout when
 * MCP_REQUEST_LOGS is set. Intended for deployed instances (Railway etc.)
 * where the server's own stdout is the only request log there is — Express
 * logs nothing by default, so misbehaving clients are otherwise invisible.
 *
 * The Authorization header is never logged verbatim, only its scheme and a
 * truncated SHA-256 fingerprint. The check happens per request (not once at
 * startup) so tests can toggle the variable.
 */
function logRequests(): RequestHandler {
    return (req: Request, res: Response, next: NextFunction): void => {
        if (!process.env.MCP_REQUEST_LOGS) {
            next()
            return
        }
        const authorization = req.headers.authorization
        const scheme = authorization?.slice(0, authorization.indexOf(' ')) || 'none'
        const fingerprint = authFingerprint(authorization)
        res.on('finish', () => {
            console.log(
                `[mcp] ${req.method} ${req.originalUrl} host=${req.headers.host ?? 'none'} ` +
                    `auth=${scheme}/${fingerprint} -> ${res.statusCode}`,
            )
        })
        next()
    }
}

export { logRequests }

import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node'
import express, {
    type Express,
    type NextFunction,
    type Request,
    type RequestHandler,
    type Response,
} from 'express'
import { getMcpServer } from './mcp-server.js'
import { requireBearerToken } from './middleware/require-bearer-token.js'
import { requireTrustedHost } from './middleware/require-trusted-host.js'
import { requireValidTodoistToken } from './middleware/require-valid-todoist-token.js'

type CreateHttpAppOptions = {
    todoistApiKey: string
    baseUrl?: string
    /** Hostnames trusted in the Host/Origin headers (DNS-rebinding protection). */
    allowedHosts: string[]
    /**
     * When set, `/mcp` requests must carry `Authorization: Bearer <token>`.
     * Without it anyone who knows the URL can run MCP tools with the
     * operator's `TODOIST_API_KEY`.
     */
    bearerToken?: string
}

/**
 * Middleware that ensures `/mcp` requests advertise both Accept types the
 * Streamable HTTP transport requires. Spec-compliant clients always send
 * `Accept: application/json, text/event-stream`; the MCP transport rejects
 * anything else with 406. Some hosted clients (e.g. Mistral's custom MCP
 * connector, whose documented probe request omits the header) fail against
 * that check, so patch the header in rather than fail their initialize.
 *
 * Both header representations are patched:
 * `NodeStreamableHTTPServerTransport` converts requests via
 * `@hono/node-server`, which reads `req.rawHeaders` (the raw wire pairs), not
 * the parsed `req.headers` object — patching only the latter is invisible to
 * the transport.
 */
function normalizeMcpAccept(req: Request, _res: Response, next: NextFunction): void {
    const accept = req.headers.accept ?? ''
    if (accept.includes('application/json') && accept.includes('text/event-stream')) {
        next()
        return
    }

    const value = 'application/json, text/event-stream'
    req.headers.accept = value
    const raw: string[] = []
    let replaced = false
    for (let i = 0; i + 1 < req.rawHeaders.length; i += 2) {
        const name = req.rawHeaders[i]
        const headerValue = req.rawHeaders[i + 1]
        if (name === undefined || headerValue === undefined) {
            continue
        }
        if (name.toLowerCase() === 'accept') {
            if (!replaced) {
                raw.push(name, value)
                replaced = true
            }
            continue
        }
        raw.push(name, headerValue)
    }
    if (!replaced) {
        raw.push('accept', value)
    }
    req.rawHeaders = raw
    next()
}

/**
 * Build the request's base URL (`scheme://host`) for the RFC 9728 Protected
 * Resource Metadata document and the `resource_metadata` challenge parameter.
 *
 * The scheme honours `X-Forwarded-Proto` (set by TLS-terminating proxies such
 * as Railway's edge), defaulting to `http` for direct connections. Only the
 * first value is used, matching proxies that append per hop.
 */
function requestBaseUrl(req: Request): string {
    const forwardedProto = Array.isArray(req.headers['x-forwarded-proto'])
        ? req.headers['x-forwarded-proto'][0]
        : req.headers['x-forwarded-proto']
    const proto = forwardedProto?.split(',')[0]?.trim() || 'http'
    const host = req.headers.host ?? 'localhost'
    return `${proto}://${host}`
}

/**
 * Build the Express app for the MCP HTTP server.
 *
 * The DNS-rebinding guard (`requireTrustedHost`) is scoped to the sensitive
 * `/mcp` routes and runs ahead of body parsing and token auth there. `/health`
 * is intentionally unguarded so deployment health probes — which send the
 * target's private IP in the Host header — keep working; it exposes no account
 * data.
 */
function createHttpApp({
    todoistApiKey,
    baseUrl,
    allowedHosts,
    bearerToken,
}: CreateHttpAppOptions): Express {
    const app = express()
    const trustedHost = requireTrustedHost({ allowedHosts })
    const bearerTokenGuard = bearerToken
        ? requireBearerToken({
              token: bearerToken,
              resourceMetadataUrl: (req: Request) =>
                  `${requestBaseUrl(req)}/.well-known/oauth-protected-resource`,
          })
        : undefined

    // Health check endpoint (no host guard — see above).
    app.get('/health', (_req: Request, res: Response) => {
        res.json({ status: 'ok' })
    })

    // RFC 9728 Protected Resource Metadata, served only when the endpoint is
    // actually protected (MCP_BEARER_TOKEN set) — the document describes how the
    // resource is protected, so without auth there is nothing to advertise.
    // Unguarded like /health: it exposes no account data and clients probe it
    // with whatever Host they were given.
    if (bearerToken) {
        app.get('/.well-known/oauth-protected-resource', (req: Request, res: Response) => {
            res.json({
                resource: `${requestBaseUrl(req)}/mcp`,
                bearer_methods_supported: ['header'],
            })
        })
    }

    // MCP endpoint - POST for requests.
    // `trustedHost` rejects untrusted Host/Origin with a cheap 403 before the
    // body is parsed. `bearerTokenGuard` (when MCP_BEARER_TOKEN is set)
    // rejects unauthenticated requests with a 401 before any work is done.
    // `normalizeMcpAccept` then patches in the Accept types the MCP transport
    // requires (clients that omit them otherwise get a 406).
    // `requireValidTodoistToken` validates the token so that invalid tokens
    // produce an HTTP 401 (per MCP spec) instead of being swallowed into a 200
    // JSON-RPC response with isError: true.
    const postHandlers: RequestHandler[] = [
        trustedHost,
        ...(bearerTokenGuard ? [bearerTokenGuard] : []),
        normalizeMcpAccept,
        express.json(),
        requireValidTodoistToken({ type: 'static', apiKey: todoistApiKey, baseUrl }),
        async (req: Request, res: Response) => {
            try {
                const transport = new NodeStreamableHTTPServerTransport({
                    sessionIdGenerator: undefined,
                })

                const server = getMcpServer({ todoistApiKey, baseUrl })
                await server.connect(transport)
                await transport.handleRequest(req, res, req.body)
            } catch (error) {
                console.error('[Error] Request handling failed:', error)
                res.status(500).json({
                    jsonrpc: '2.0',
                    error: {
                        code: -32603,
                        message: 'Internal server error',
                    },
                    id: null,
                })
            }
        },
    ]
    app.post('/mcp', ...postHandlers)

    // MCP endpoint - GET returns 405 (needed for MCP client compatibility).
    app.get('/mcp', trustedHost, (_req: Request, res: Response) => {
        res.status(405).set('Allow', 'POST').send('Method Not Allowed')
    })

    return app
}

export { createHttpApp, type CreateHttpAppOptions }

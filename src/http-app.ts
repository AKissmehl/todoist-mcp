import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node'
import express, {
    type Express,
    type NextFunction,
    type Request,
    type RequestHandler,
    type Response,
} from 'express'
import { getMcpServer } from './mcp-server.js'
import { logRequests } from './middleware/log-requests.js'
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
    // Logs one line per request when MCP_REQUEST_LOGS is set — the only way to
    // see what a hosted client (e.g. Mistral's production runner) actually
    // sends, since Express logs nothing by default.
    app.use(logRequests())
    const trustedHost = requireTrustedHost({ allowedHosts })
    // Plain 'Bearer' challenge, deliberately without an RFC 9728
    // resource_metadata pointer: clients that follow the pointer (Mistral's
    // connector) treat any Protected Resource Metadata document as proof of an
    // OAuth authorization server and then fail fetching
    // /.well-known/oauth-authorization-server — this server has no OAuth, the
    // challenge is the whole story. For the same reason the metadata document
    // itself is not served at /.well-known/oauth-protected-resource: Mistral's
    // connector probes that path directly and enters OAuth mode even when
    // `authorization_servers` is an explicit empty array.
    const bearerTokenGuard = bearerToken ? requireBearerToken({ token: bearerToken }) : undefined

    // Health check endpoint (no host guard — see above).
    app.get('/health', (_req: Request, res: Response) => {
        res.json({ status: 'ok' })
    })

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

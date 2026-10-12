import type { Request, Response } from 'express'
import { type Mock, beforeEach, describe, expect, it, vi } from 'vitest'

import { requireBearerToken } from './require-bearer-token.js'

function createMockRes(): Response {
    const res = {
        status: vi.fn().mockReturnThis(),
        set: vi.fn().mockReturnThis(),
        json: vi.fn().mockReturnThis(),
    }
    return res as unknown as Response
}

function createReq(headers: { authorization?: string }): Request {
    return { headers } as unknown as Request
}

describe('requireBearerToken', () => {
    let next: Mock

    beforeEach(() => {
        next = vi.fn()
    })

    it('allows a request with the correct Bearer token', () => {
        const middleware = requireBearerToken({ token: 'secret-token' })
        const res = createMockRes()
        middleware(createReq({ authorization: 'Bearer secret-token' }), res, next)

        expect(next).toHaveBeenCalledOnce()
        expect(res.status).not.toHaveBeenCalled()
    })

    it('rejects a request without an Authorization header with 401', () => {
        const middleware = requireBearerToken({ token: 'secret-token' })
        const res = createMockRes()
        middleware(createReq({}), res, next)

        expect(next).not.toHaveBeenCalled()
        expect(res.status).toHaveBeenCalledWith(401)
        expect(res.set).toHaveBeenCalledWith('WWW-Authenticate', 'Bearer')
        expect(res.json).toHaveBeenCalledWith({
            error: 'invalid_token',
            error_description: 'A valid Authorization: Bearer token is required',
        })
    })

    it('allows the case-insensitive Bearer scheme (RFC 7235)', () => {
        const middleware = requireBearerToken({ token: 'secret-token' })
        const res = createMockRes()
        middleware(createReq({ authorization: 'bearer secret-token' }), res, next)

        expect(next).toHaveBeenCalledOnce()
    })

    it.each([['Bearer wrong-token'], ['Bearer '], ['Basic secret-token'], ['secret-token']])(
        'rejects Authorization %s with 401',
        (authorization) => {
            const middleware = requireBearerToken({ token: 'secret-token' })
            const res = createMockRes()
            middleware(createReq({ authorization }), res, next)

            expect(next).not.toHaveBeenCalled()
            expect(res.status).toHaveBeenCalledWith(401)
        },
    )

    it('tolerates surrounding whitespace after the scheme', () => {
        const middleware = requireBearerToken({ token: 'secret-token' })
        const res = createMockRes()
        middleware(createReq({ authorization: 'Bearer   secret-token  ' }), res, next)

        expect(next).toHaveBeenCalledOnce()
    })

    it('advertises the RFC 9728 resource_metadata URL when the option is set', () => {
        const middleware = requireBearerToken({
            token: 'secret-token',
            resourceMetadataUrl: () => 'https://example.com/.well-known/oauth-protected-resource',
        })
        const res = createMockRes()
        middleware(createReq({}), res, next)

        expect(next).not.toHaveBeenCalled()
        expect(res.set).toHaveBeenCalledWith(
            'WWW-Authenticate',
            'Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"',
        )
    })

    it('sends a plain Bearer challenge when no resource_metadata URL is set', () => {
        const middleware = requireBearerToken({ token: 'secret-token' })
        const res = createMockRes()
        middleware(createReq({}), res, next)

        expect(res.set).toHaveBeenCalledWith('WWW-Authenticate', 'Bearer')
    })
})

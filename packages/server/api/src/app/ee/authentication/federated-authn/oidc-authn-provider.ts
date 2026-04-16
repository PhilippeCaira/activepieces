import {
    ActivepiecesError,
    ErrorCode,
    isNil,
} from '@activepieces/shared'
import { FastifyBaseLogger } from 'fastify'
import { federatedAuthnService } from './federated-authn-service'

export type OidcAuthnIdToken = {
    email: string
    firstName: string
    lastName: string
    imageUrl?: string
}

type OidcDiscovery = {
    authorization_endpoint: string
    token_endpoint: string
    userinfo_endpoint: string
}

const discoveryCache = new Map<string, OidcDiscovery>()

async function discover(issuer: string): Promise<OidcDiscovery> {
    const cached = discoveryCache.get(issuer)
    if (cached) return cached

    const url = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`
    const resp = await fetch(url)
    if (!resp.ok) {
        throw new ActivepiecesError({
            code: ErrorCode.INVALID_CREDENTIALS,
            params: null,
        }, `OIDC discovery failed for ${issuer}: ${resp.status}`)
    }
    const config = await resp.json() as OidcDiscovery
    discoveryCache.set(issuer, config)
    return config
}

export const oidcAuthnProvider = (log: FastifyBaseLogger) => ({
    async getLoginUrl(params: {
        issuer: string
        clientId: string
        platformId: string | undefined
    }): Promise<string> {
        const { issuer, clientId, platformId } = params
        const disc = await discover(issuer)
        const loginUrl = new URL(disc.authorization_endpoint)
        loginUrl.searchParams.set('client_id', clientId)
        loginUrl.searchParams.set(
            'redirect_uri',
            await federatedAuthnService(log).getThirdPartyRedirectUrl(platformId),
        )
        loginUrl.searchParams.set('scope', 'openid email profile')
        loginUrl.searchParams.set('response_type', 'code')
        return loginUrl.href
    },

    async authenticate(params: {
        issuer: string
        clientId: string
        clientSecret: string
        authorizationCode: string
        platformId: string | undefined
    }): Promise<OidcAuthnIdToken> {
        const { issuer, clientId, clientSecret, authorizationCode, platformId } = params
        const disc = await discover(issuer)

        const tokenResp = await fetch(disc.token_endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                code: authorizationCode,
                client_id: clientId,
                client_secret: clientSecret,
                redirect_uri: await federatedAuthnService(log).getThirdPartyRedirectUrl(platformId),
                grant_type: 'authorization_code',
            }),
        })

        const tokenBody = await tokenResp.json() as { access_token?: string }
        if (isNil(tokenBody.access_token)) {
            throw new ActivepiecesError({
                code: ErrorCode.INVALID_CREDENTIALS,
                params: null,
            }, 'OIDC token exchange failed')
        }

        const userinfoResp = await fetch(disc.userinfo_endpoint, {
            headers: { Authorization: `Bearer ${tokenBody.access_token}` },
        })
        const userinfo = await userinfoResp.json() as {
            email?: string
            name?: string
            given_name?: string
            family_name?: string
            picture?: string
        }

        if (isNil(userinfo.email)) {
            throw new ActivepiecesError({
                code: ErrorCode.INVALID_CREDENTIALS,
                params: null,
            }, 'OIDC userinfo did not return email')
        }

        return {
            email: userinfo.email,
            firstName: userinfo.given_name ?? userinfo.name?.split(' ')[0] ?? '',
            lastName: userinfo.family_name ?? userinfo.name?.split(' ').slice(1).join(' ') ?? '',
            imageUrl: userinfo.picture,
        }
    },
})

import { assertNotNullOrUndefined, AuthenticationResponse,
    FederatedAuthnLoginResponse,
    isNil,
    ThirdPartyAuthnProviderEnum,
    UserIdentityProvider,
} from '@activepieces/shared'
import { FastifyBaseLogger } from 'fastify'
import { authenticationService } from '../../../authentication/authentication.service'
import { system } from '../../../helper/system/system'
import { AppSystemProp } from '../../../helper/system/system-props'
import { platformService } from '../../../platform/platform.service'
import { domainHelper } from '../../custom-domains/domain-helper'
import { googleAuthnProvider } from './google-authn-provider'
import { oidcAuthnProvider } from './oidc-authn-provider'

export const federatedAuthnService = (log: FastifyBaseLogger) => ({
    async login({
        platformId,
        providerName,
    }: LoginParams): Promise<FederatedAuthnLoginResponse> {
        switch (providerName) {
            case ThirdPartyAuthnProviderEnum.OIDC: {
                const { issuer, clientId } = await getOidcConfig(platformId, log)
                const loginUrl = await oidcAuthnProvider(log).getLoginUrl({
                    issuer,
                    clientId,
                    platformId,
                })
                return { loginUrl }
            }
            case ThirdPartyAuthnProviderEnum.GOOGLE:
            default: {
                const { clientId } = await getGoogleClientIdAndSecret(platformId, log)
                const loginUrl = await googleAuthnProvider(log).getLoginUrl({
                    clientId,
                    platformId,
                })
                return { loginUrl }
            }
        }
    },

    async claim({
        platformId,
        code,
        providerName,
    }: ClaimParams): Promise<AuthenticationResponse> {
        switch (providerName) {
            case ThirdPartyAuthnProviderEnum.OIDC: {
                const { issuer, clientId, clientSecret } = await getOidcConfig(platformId, log)
                const idToken = await oidcAuthnProvider(log).authenticate({
                    issuer,
                    clientId,
                    clientSecret,
                    authorizationCode: code,
                    platformId,
                })
                return authenticationService(log).federatedAuthn({
                    email: idToken.email,
                    firstName: idToken.firstName ?? 'john',
                    lastName: idToken.lastName ?? 'doe',
                    trackEvents: true,
                    newsLetter: true,
                    provider: UserIdentityProvider.OIDC,
                    predefinedPlatformId: platformId ?? null,
                    imageUrl: idToken.imageUrl,
                })
            }
            case ThirdPartyAuthnProviderEnum.GOOGLE:
            default: {
                const { clientId, clientSecret } = await getGoogleClientIdAndSecret(platformId, log)
                const idToken = await googleAuthnProvider(log).authenticate({
                    clientId,
                    clientSecret,
                    authorizationCode: code,
                    platformId,
                })
                return authenticationService(log).federatedAuthn({
                    email: idToken.email,
                    firstName: idToken.firstName ?? 'john',
                    lastName: idToken.lastName ?? 'doe',
                    trackEvents: true,
                    newsLetter: true,
                    provider: UserIdentityProvider.GOOGLE,
                    predefinedPlatformId: platformId ?? null,
                    imageUrl: idToken.imageUrl,
                })
            }
        }
    },
    async getThirdPartyRedirectUrl(
        platformId: string | undefined,
    ): Promise<string> {
        return domainHelper.getInternalUrl({
            path: '/redirect',
            platformId,
        })
    },
})

async function getGoogleClientIdAndSecret(platformId: string | undefined, log: FastifyBaseLogger) {
    if (isNil(platformId)) {
        return {
            clientId: system.getOrThrow(AppSystemProp.GOOGLE_CLIENT_ID),
            clientSecret: system.getOrThrow(AppSystemProp.GOOGLE_CLIENT_SECRET),
        }
    }
    const platform = await platformService(log).getOneOrThrow(platformId)
    const clientInformation = platform.federatedAuthProviders.google
    assertNotNullOrUndefined(clientInformation, 'Google client information is not defined')
    return {
        clientId: clientInformation.clientId,
        clientSecret: clientInformation.clientSecret,
    }
}

async function getOidcConfig(platformId: string | undefined, log: FastifyBaseLogger) {
    if (isNil(platformId)) {
        return {
            issuer: system.getOrThrow(AppSystemProp.OIDC_ISSUER),
            clientId: system.getOrThrow(AppSystemProp.OIDC_CLIENT_ID),
            clientSecret: system.getOrThrow(AppSystemProp.OIDC_CLIENT_SECRET),
        }
    }
    const platform = await platformService(log).getOneOrThrow(platformId)
    const oidcConfig = platform.federatedAuthProviders.oidc
    assertNotNullOrUndefined(oidcConfig, 'OIDC configuration is not defined')
    return {
        issuer: oidcConfig.issuer,
        clientId: oidcConfig.clientId,
        clientSecret: oidcConfig.clientSecret,
    }
}

type LoginParams = {
    platformId: string | undefined
    providerName: ThirdPartyAuthnProviderEnum
}

type ClaimParams = {
    platformId: string | undefined
    code: string
    providerName: ThirdPartyAuthnProviderEnum
}

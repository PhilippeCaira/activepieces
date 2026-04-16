export enum ThirdPartyAuthnProviderEnum {
    GOOGLE = 'google',
    SAML = 'saml',
    OIDC = 'oidc',
}

export type ThirdPartyAuthnProvidersToShowMap = {
    [k in ThirdPartyAuthnProviderEnum]: boolean;
}
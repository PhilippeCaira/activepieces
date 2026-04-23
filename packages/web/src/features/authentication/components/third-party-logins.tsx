import {
  ApFlagId,
  ThirdPartyAuthnProviderEnum,
  ThirdPartyAuthnProvidersToShowMap,
} from '@activepieces/shared';
import { t } from 'i18next';
import React, { useEffect, useRef } from 'react';

import { authenticationApi } from '@/api/authentication-api';
import GoogleIcon from '@/assets/img/custom/auth/google-icon.svg';
import OidcIcon from '@/assets/img/custom/auth/oidc.svg';
import SamlIcon from '@/assets/img/custom/auth/saml.svg';
import { Button } from '@/components/ui/button';
import { internalErrorToast } from '@/components/ui/sonner';
import { oauth2Utils } from '@/features/connections/utils/oauth2-utils';
import { flagsHooks } from '@/hooks/flags-hooks';

// Fork OIDC : déclenche automatiquement le flow SSO si l'env Vite
// VITE_AP_OIDC_AUTO_REDIRECT=true et le user n'a pas déjà d'en-tête
// local=1 dans la querystring (escape hatch pour debug admin).
// Accès direct sans cast TS pour que Vite define matche littéralement.
const AUTO_OIDC_REDIRECT =
  import.meta.env.VITE_AP_OIDC_AUTO_REDIRECT === 'true';

const ThirdPartyIcon = ({ icon }: { icon: string }) => {
  return <img src={icon} alt="icon" width={24} height={24} className="mr-2" />;
};

const ThirdPartyLogin = React.memo(({ isSignUp }: { isSignUp: boolean }) => {
  const { data: thirdPartyAuthProviders } =
    flagsHooks.useFlag<ThirdPartyAuthnProvidersToShowMap>(
      ApFlagId.THIRD_PARTY_AUTH_PROVIDERS_TO_SHOW_MAP,
    );
  const { data: thirdPartyRedirectUrl } = flagsHooks.useFlag<string>(
    ApFlagId.THIRD_PARTY_AUTH_PROVIDER_REDIRECT_URL,
  );
  const thirdPartyLogin = oauth2Utils.useThirdPartyLogin();

  const handleProviderClick = async (
    event: React.MouseEvent<HTMLButtonElement, MouseEvent>,
    providerName: ThirdPartyAuthnProviderEnum,
  ) => {
    event.preventDefault();
    event.stopPropagation();
    const { loginUrl } = await authenticationApi.getFederatedAuthLoginUrl(
      providerName,
    );

    if (!loginUrl || !thirdPartyRedirectUrl) {
      internalErrorToast();
      return;
    }
    thirdPartyLogin(loginUrl, providerName);
  };

  // Fork OIDC : déclenche le flow OIDC automatiquement au mount si
  // AUTO_OIDC_REDIRECT et provider OIDC disponible. Évite aux users déjà
  // loggés dans Zitadel d'avoir à cliquer. Escape hatch : ?local=1.
  const hasAutoTriggered = useRef(false);
  useEffect(() => {
    if (!AUTO_OIDC_REDIRECT) return;
    if (hasAutoTriggered.current) return;
    if (typeof window === 'undefined') return;
    const params = new URLSearchParams(window.location.search);
    if (params.get('local') === '1') return;
    if (!thirdPartyAuthProviders?.oidc) return;
    if (!thirdPartyRedirectUrl) return;
    hasAutoTriggered.current = true;
    (async () => {
      try {
        const { loginUrl } = await authenticationApi.getFederatedAuthLoginUrl(
          ThirdPartyAuthnProviderEnum.OIDC,
        );
        if (loginUrl) thirdPartyLogin(loginUrl, ThirdPartyAuthnProviderEnum.OIDC);
      } catch {
        // silent fail — l'user cliquera le bouton manuellement
      }
    })();
  }, [thirdPartyAuthProviders?.oidc, thirdPartyRedirectUrl, thirdPartyLogin]);

  const signInWithSaml = () =>
    (window.location.href = '/api/v1/authn/saml/login');

  return (
    <div className="flex flex-col gap-4">
      {thirdPartyAuthProviders?.google && (
        <Button
          variant="outline"
          className="w-full rounded-sm"
          onClick={(e) =>
            handleProviderClick(e, ThirdPartyAuthnProviderEnum.GOOGLE)
          }
        >
          <ThirdPartyIcon icon={GoogleIcon} />
          {isSignUp
            ? `${t(`Sign up With`)} ${t('Google')}`
            : `${t(`Sign in With`)} ${t('Google')}`}
        </Button>
      )}
      {thirdPartyAuthProviders?.saml && (
        <Button
          variant="outline"
          className="w-full rounded-sm"
          onClick={signInWithSaml}
        >
          <ThirdPartyIcon icon={SamlIcon} />
          {isSignUp
            ? `${t(`Sign up With`)} ${t('SAML')}`
            : `${t(`Sign in With`)} ${t('SAML')}`}
        </Button>
      )}
      {thirdPartyAuthProviders?.oidc && (
        <Button
          variant="outline"
          className="w-full rounded-sm"
          onClick={(e) =>
            handleProviderClick(e, ThirdPartyAuthnProviderEnum.OIDC)
          }
        >
          <ThirdPartyIcon icon={OidcIcon} />
          {isSignUp
            ? `${t(`Sign up With`)} ${t('SSO')}`
            : `${t(`Sign in With`)} ${t('SSO')}`}
        </Button>
      )}
    </div>
  );
});

ThirdPartyLogin.displayName = 'ThirdPartyLogin';
export { ThirdPartyLogin };

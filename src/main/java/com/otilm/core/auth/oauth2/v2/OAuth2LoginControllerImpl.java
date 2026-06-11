package com.otilm.core.auth.oauth2.v2;

import com.otilm.api.interfaces.core.web.v2.OAuth2LoginController;
import com.otilm.api.model.core.auth.LoginProviderDto;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.util.OAuth2LoginFlowHelper;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.service.v2.OAuth2LoginService;
import com.otilm.core.util.OAuth2Constants;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.List;

@RestController
@Slf4j
public class OAuth2LoginControllerImpl implements OAuth2LoginController {

    private AuditLogInternalService auditLogService;
    private OAuth2LoginService oauth2LoginService;

    @Autowired
    public void setAuditLogService(AuditLogInternalService auditLogService) {
        this.auditLogService = auditLogService;
    }

    @Autowired
    public void setOauth2LoginService(OAuth2LoginService oauth2LoginService) {
        this.oauth2LoginService = oauth2LoginService;
    }

    @Override
    public List<LoginProviderDto> getOAuth2Providers(String error) {
        HttpServletRequest request = getHttpServletRequest();
        request.getSession().setAttribute(OAuth2Constants.SERVLET_CONTEXT_SESSION_ATTRIBUTE, ServletUriComponentsBuilder.fromCurrentContextPath().build().getPath());

        if (error != null) {
            request.getSession().invalidate();
            throw new PlatformAuthenticationException("Error during authentication: " + error);
        }

        // Work only with properly configured OAuth2 providers.
        List<OAuth2ProviderSettingsDto> oauth2Providers = oauth2LoginService.getValidOAuth2Providers();

        return oauth2Providers.stream()
                .map(provider -> {
                    LoginProviderDto loginProvider = new LoginProviderDto();
                    loginProvider.setName(provider.getName());
                    String loginUrl = ServletUriComponentsBuilder.fromCurrentContextPath()
                            .path("/v2/oauth2/providers/{provider}/login")
                            .buildAndExpand(provider.getName())
                            .encode()
                            .toUriString();
                    loginProvider.setLoginUrl(loginUrl);
                    return loginProvider;
                })
                .toList();
    }

    @Override
    public ResponseEntity<Void> loginWithProvider(String provider, String redirect) {
        String baseUrl = ServletUriComponentsBuilder.fromCurrentRequestUri()
                .replacePath(null)
                .build()
                .toUriString();

        String validatedRedirectUrl = oauth2LoginService.validateAndNormalizeRedirect(redirect);
        if (validatedRedirectUrl == null) {
            String errorMessage = "Missing or invalid redirect URL. Please start the login from the beginning.";
            auditLogService.logAuthentication(Operation.LOGIN, OperationResult.FAILURE, errorMessage, null);
            throw new PlatformAuthenticationException(errorMessage);
        }

        HttpServletRequest request = getHttpServletRequest();
        request.getSession(true).setAttribute(OAuth2Constants.REDIRECT_URL_SESSION_ATTRIBUTE, baseUrl + validatedRedirectUrl);

        OAuth2ProviderSettingsDto providerSettings = OAuth2LoginFlowHelper.resolveProviderOrThrow(provider, request, oauth2LoginService, auditLogService);

        request.getSession().setAttribute(OAuth2Constants.SERVLET_CONTEXT_SESSION_ATTRIBUTE, ServletUriComponentsBuilder.fromCurrentContextPath().build().getPath());
        request.getSession().setMaxInactiveInterval(providerSettings.getSessionMaxInactiveInterval());

        String redirectUrl = ServletUriComponentsBuilder.fromCurrentContextPath().build().getPath() + "/oauth2/authorization/" + provider;
        return ResponseEntity.status(HttpStatus.FOUND).header("Location", redirectUrl).build();
    }

    private HttpServletRequest getHttpServletRequest() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            throw new IllegalStateException("No ServletRequestAttributes found in RequestContextHolder");
        }
        return attributes.getRequest();
    }
}

package com.otilm.core.auth.oauth2;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.LoginProviderDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.auth.oauth2.v2.OAuth2LoginControllerImpl;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.service.v2.OAuth2LoginService;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.OAuth2Constants;
import com.otilm.core.util.OAuth2LoginFlowHelper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

@Controller
public class LoginController {

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

    /**
     * @deprecated since 2.17.0, use {@link OAuth2LoginControllerImpl#getOAuth2Providers} instead
     */
    @GetMapping(
            value = "/login",
            produces = {"application/json"}
    )
    @ResponseBody
    @Deprecated(forRemoval = true, since = "2.17.0")
    public ResponseEntity<List<LoginProviderDto>> login(@RequestParam(value = "redirect", required = false) String redirectUrl, HttpServletRequest request, HttpServletResponse response, @RequestParam(value = "error", required = false) String error) {

        request.getSession().setAttribute(OAuth2Constants.SERVLET_CONTEXT_SESSION_ATTRIBUTE, ServletUriComponentsBuilder.fromCurrentContextPath().build().getPath());

        if (error != null) {
            request.getSession().invalidate();
            throw new PlatformAuthenticationException("Error during authentication: " + error);
        }

        String baseUrl = ServletUriComponentsBuilder.fromCurrentRequestUri()
                .replacePath(null)
                .build()
                .toUriString();

        String validatedRedirectUrl = oauth2LoginService.validateAndNormalizeRedirect(redirectUrl);
        if (validatedRedirectUrl != null) {
            request.getSession().setAttribute(OAuth2Constants.REDIRECT_URL_SESSION_ATTRIBUTE, baseUrl + validatedRedirectUrl);
        } else {
            throw new PlatformAuthenticationException("No redirect URL provided for login or redirect URL is invalid");
        }

        // Display only properly configured providers
        List<OAuth2ProviderSettingsDto> oauth2Providers = oauth2LoginService.getValidOAuth2Providers();
        if (oauth2Providers.size() == 1) {
            request.getSession().setMaxInactiveInterval(oauth2Providers.getFirst().getSessionMaxInactiveInterval());
            String redirectPath = ServletUriComponentsBuilder.fromCurrentContextPath()
                    .path("/oauth2/authorization/{provider}")
                    .buildAndExpand(oauth2Providers.getFirst().getName())
                    .encode()
                    .toUriString();
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(URI.create(redirectPath));
            return new ResponseEntity<>(null, headers, HttpStatus.FOUND);
        }

        List<LoginProviderDto> loginProviders = oauth2Providers.stream()
                .map(provider -> {
                    LoginProviderDto loginProvider = new LoginProviderDto();
                    loginProvider.setName(provider.getName());
                    String loginUrl = ServletUriComponentsBuilder.fromCurrentContextPath()
                            .path("/oauth2/authorization/{provider}/prepare")
                            .buildAndExpand(provider.getName())
                            .encode()
                            .toUriString();
                    loginProvider.setLoginUrl(loginUrl);
                    return loginProvider;
                })
                .toList();

        return new ResponseEntity<>(loginProviders, HttpStatus.OK);
    }

    /**
     * @deprecated since 2.17.0, use {@link OAuth2LoginControllerImpl#loginWithProvider} instead
     */
    @GetMapping("/oauth2/authorization/{provider}/prepare")
    @Deprecated(forRemoval = true, since = "2.17.0")
    public void loginWithProvider(@PathVariable String provider, @RequestParam(value = "redirect", required = false) String redirect, HttpServletResponse response, HttpServletRequest request) throws IOException {
        String baseUrl = ServletUriComponentsBuilder.fromCurrentRequestUri()
                .replacePath(null)
                .build()
                .toUriString();

        String validatedRedirectUrl = oauth2LoginService.validateAndNormalizeRedirect(redirect);
        if (validatedRedirectUrl != null) {
            request.getSession(true).setAttribute(OAuth2Constants.REDIRECT_URL_SESSION_ATTRIBUTE, baseUrl + validatedRedirectUrl);
        }

        OAuth2ProviderSettingsDto providerSettings = OAuth2LoginFlowHelper.resolveProviderOrThrow(provider, request, oauth2LoginService, auditLogService);

        if (request.getSession(false) == null || request.getSession().getAttribute(OAuth2Constants.REDIRECT_URL_SESSION_ATTRIBUTE) == null) {
            throw new PlatformAuthenticationException("Missing redirect URL. Please start the login from the beginning.");
        }

        request.getSession().setMaxInactiveInterval(providerSettings.getSessionMaxInactiveInterval());
        response.sendRedirect(ServletUriComponentsBuilder.fromCurrentContextPath().build().getPath() + "/oauth2/authorization/" + provider);
    }

    @GetMapping("/oauth2/{provider}/jwkSet")
    public ResponseEntity<String> getJwkSet(@PathVariable String provider) {
        AuthenticationSettingsDto authenticationSettings = SettingsCache.getSettings(SettingsSection.AUTHENTICATION);

        if (authenticationSettings.getOAuth2Providers() == null || authenticationSettings.getOAuth2Providers().get(provider) == null) {
            throw new ValidationException("Provider %s does not exist.".formatted(provider));
        }

        String jwkSetEncoded = authenticationSettings.getOAuth2Providers().get(provider).getJwkSet();
        if (jwkSetEncoded == null) {
            throw new ValidationException("Provider %s does not have JWK Set set up.".formatted(provider));
        }

        String jwkSet = new String(Base64.getDecoder().decode(jwkSetEncoded), StandardCharsets.UTF_8);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-type", MediaType.APPLICATION_JSON_VALUE);
        return new ResponseEntity<>(jwkSet, headers, HttpStatus.OK);
    }

}
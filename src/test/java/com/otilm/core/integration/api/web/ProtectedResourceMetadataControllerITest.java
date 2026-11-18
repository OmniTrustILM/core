package com.otilm.core.integration.api.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ApplicationSettingsDto;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.BaseSpringBootTestNoAuth;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The annotations and the mock set are deliberately identical to {@code PublicBrandingControllerITest}, so both classes
 * share one cached Spring context; the authentication settings are set per test rather than wired into the context.
 */
@AutoConfigureMockMvc
@TestPropertySource(properties = "server.servlet.context-path=")
class ProtectedResourceMetadataControllerITest extends BaseSpringBootTestNoAuth {

    private static final String PATH = "/.well-known/oauth-protected-resource/api";

    private static final String CLIENT_SECRET = "confidential-secret";

    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private MockMvc mvc;

    @Autowired
    private SettingsCache settingsCache;

    @MockitoBean
    private JdbcIndexedSessionRepository sessionRepository;

    @MockitoBean
    private GenericConversionService springSessionConversionService;

    @SuppressWarnings("rawtypes")
    @MockitoBean
    private SessionRepositoryFilter springSessionRepositoryFilter;

    @BeforeEach
    void resetSettingsAndPassTheSessionFilterThrough() throws Exception {
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, new AuthenticationSettingsDto());

        Mockito.doAnswer(invocation -> {
            ServletRequest request = invocation.getArgument(0);
            ServletResponse response = invocation.getArgument(1);
            FilterChain filterChain = invocation.getArgument(2);
            filterChain.doFilter(request, response);
            return null;
        }).when(springSessionRepositoryFilter).doFilter(Mockito.any(), Mockito.any(), Mockito.any());
    }

    @Test
    void returnsEmptyLists_whenNoProviderIsEnabledForApplications() throws Exception {
        // given
        cacheProviders(createProvider("disabled", "https://disabled.example.com", null));

        // when
        JsonNode document = fetchDocument();

        // then
        assertThat(document.get("authorization_servers")).isEmpty();
        assertThat(document.get("otilm_authorization_servers")).isEmpty();
        assertThat(document.get("resource").asText()).isEqualTo("http://localhost/api");
    }

    @Test
    void listsExactlyTheEnabledProviders_whenSeveralAreConfigured() throws Exception {
        // given
        var configured = createApplications(true);
        configured.setClientId("public-client");
        configured.setScopes(List.of("openid"));
        cacheProviders(createProvider("enabled", "https://enabled.example.com", configured),
                createProvider("disabled", "https://disabled.example.com", createApplications(false)));

        // when
        JsonNode document = fetchDocument();

        // then
        assertThat(document.get("authorization_servers")).hasSize(1);
        assertThat(document.get("authorization_servers").get(0).asText()).isEqualTo("https://enabled.example.com");
        JsonNode server = document.get("otilm_authorization_servers").get(0);
        assertThat(server.get("issuer").asText()).isEqualTo("https://enabled.example.com");
        assertThat(server.get("name").asText()).isEqualTo("enabled");
        assertThat(server.get("client_id").asText()).isEqualTo("public-client");
        assertThat(server.get("scopes").get(0).asText()).isEqualTo("openid");
        assertThat(server.has("resource")).isFalse();
    }

    @Test
    void carriesOnlyTheDocumentKeysAndNoSecret_whenAProviderIsEnabled() throws Exception {
        // given
        var provider = createProvider("enabled", "https://enabled.example.com", createApplications(true));
        provider.setClientSecret(CLIENT_SECRET);
        provider.setJwkSetUrl("https://internal.example.com/jwks");
        cacheProviders(provider);

        // when
        String body = fetchBody();

        // then
        assertThat(extractKeys(mapper.readTree(body)))
                .containsExactlyInAnyOrder("resource", "resource_name", "authorization_servers",
                        "bearer_methods_supported", "otilm_authorization_servers");
        assertThat(body).doesNotContain(CLIENT_SECRET).doesNotContain("internal.example.com");
    }

    @Test
    void refusesAWrite_whenTheMetadataPathIsPosted() throws Exception {
        // given
        var anonymousWrite = post(PATH);

        // when
        ResultActions result = mvc.perform(anonymousWrite);

        // then
        result.andExpect(status().is4xxClientError());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String fetchBody() throws Exception {
        return mvc.perform(get(PATH)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    }

    private JsonNode fetchDocument() throws Exception {
        return mapper.readTree(fetchBody());
    }

    private void cacheProviders(OAuth2ProviderSettingsDto... providers) {
        var settings = new AuthenticationSettingsDto();
        var byName = new java.util.HashMap<String, OAuth2ProviderSettingsDto>();
        for (OAuth2ProviderSettingsDto provider : providers) {
            byName.put(provider.getName(), provider);
        }
        settings.setOAuth2Providers(byName);
        settingsCache.cacheSettings(SettingsSection.AUTHENTICATION, settings);
    }

    private static Set<String> extractKeys(JsonNode node) {
        var keys = new ArrayList<String>();
        node.fieldNames().forEachRemaining(keys::add);
        return Set.copyOf(keys);
    }

    private static OAuth2ProviderSettingsDto createProvider(String name, String issuerUrl,
            OAuth2ApplicationSettingsDto applications) {
        var provider = new OAuth2ProviderSettingsDto();
        provider.setName(name);
        provider.setIssuerUrl(issuerUrl);
        provider.setApplications(applications);
        return provider;
    }

    private static OAuth2ApplicationSettingsDto createApplications(boolean enabled) {
        var applications = new OAuth2ApplicationSettingsDto();
        applications.setEnabled(enabled);
        return applications;
    }
}

package com.otilm.core.integration.service.v3;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.authority.AuthorityInstanceRequestDto;
import com.otilm.api.model.client.authority.AuthorityInstanceUpdateRequestDto;
import com.otilm.api.model.client.metadata.MetadataResponseDto;
import com.otilm.api.model.client.metadata.ResponseMetadata;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.authority.AuthorityInstanceDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.repository.AttributeContent2ObjectRepository;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.AuthorityInstanceExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.builders.AuthorityFixtures;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.otilm.core.util.builders.DataAttributeV3Builder.aDataAttribute;
import static com.otilm.core.util.builders.RequestAttributeV3Builder.aCustomAttribute;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Metadata a v3 authority connector returns from the connection check: stored on create and edit as the authority's
 * whole metadata set, shown on the detail, and removed with the authority.
 */
class AuthorityMetadataITest extends BaseSpringBootTest {

    private static final String CONNECTION_PATH = "/v3/authorityProvider/authorities";
    private static final String ATTRIBUTES_PATH = "/v3/authorityProvider/authorities/attributes";
    private static final UUID DIRECTORY_URL_UUID = UUID.fromString("6a7c2f8e-4b1d-4f3a-9c0e-2d5b8a1e7f40");
    private static final String DIRECTORY_URL = "directoryUrl";
    private static final String ACCOUNT_URL = "acmeAccountUrl";
    private static final String KEY_THUMBPRINT = "acmeAccountKeyThumbprint";

    @Autowired
    private AuthorityInstanceExternalService authorityInstanceService;
    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private AttributeContent2ObjectRepository attributeContent2ObjectRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    private WireMockServer wireMockServer;
    private AuthorityInstanceReference authority;

    @BeforeEach
    void createV3Authority() throws Exception {
        wireMockServer = new WireMockServer(LoopbackWireMock.options());
        wireMockServer.start();
        WireMock.configureFor(LoopbackWireMock.HOST, wireMockServer.port());
        AuthorityFixtures.Fixture fixture = AuthorityFixtures
                .v3Authority(new AuthorityFixtures.Repos(connectorRepository, functionGroupRepository,
                        connector2FunctionGroupRepository, authorityInstanceReferenceRepository, raProfileRepository,
                        connectorInterfaceRepository), wireMockServer);
        authority = fixture.authority();
        // the fixture's RA profile would block deleting the authority
        raProfileRepository.delete(fixture.raProfile());
        DataAttributeV3 directoryUrl = aDataAttribute().withUuid(DIRECTORY_URL_UUID).withName(DIRECTORY_URL).build();
        wireMockServer
                .stubFor(get(urlEqualTo(ATTRIBUTES_PATH))
                        .willReturn(WireMock.okJson(new ObjectMapper().writeValueAsString(List.of(directoryUrl)))));
    }

    @AfterEach
    void stopConnector() {
        wireMockServer.stop();
    }

    @Test
    void storesTheReportedMetadata_whenAnAuthorityIsCreated() throws Exception {
        // given
        var accountUrl = "https://acme.example/acct/1";
        stubConnectionCheck(buildMetadataAnswer(buildMetadataJson(ACCOUNT_URL, accountUrl)));
        var request = new AuthorityInstanceRequestDto();
        request.setName("created-v3-authority");
        request.setConnectorUuid(authority.getConnectorUuid().toString());
        request.setInterfaceUuid(authority.getConnectorInterfaceUuid());
        request.setAttributes(buildDirectoryUrlAttributes("https://acme.example/directory"));

        // when
        AuthorityInstanceDto created = authorityInstanceService.createAuthorityInstance(request);

        // then
        assertThat(loadMetadataValues(created.getUuid())).containsExactly(Map.entry(ACCOUNT_URL, accountUrl));
    }

    @Test
    void replacesTheWholeMetadataSet_whenAnAuthorityIsEdited() throws Exception {
        // given
        stubConnectionCheck(buildMetadataAnswer(buildMetadataJson(ACCOUNT_URL, "https://acme.example/acct/1") + ","
                + buildMetadataJson(KEY_THUMBPRINT, "old-thumbprint")));
        edit("https://acme.example/directory");
        var newAccountUrl = "https://acme.example/acct/2";
        stubConnectionCheck(buildMetadataAnswer(buildMetadataJson(ACCOUNT_URL, newAccountUrl)));

        // when
        edit("https://acme.example/directory");

        // then
        assertThat(loadMetadataValues(authority.getUuid().toString()))
                .containsExactly(Map.entry(ACCOUNT_URL, newAccountUrl));
    }

    @Test
    void clearsTheMetadata_whenTheConnectorReportsNone() throws Exception {
        // given
        stubConnectionCheck(buildMetadataAnswer(buildMetadataJson(ACCOUNT_URL, "https://acme.example/acct/1")));
        edit("https://acme.example/directory");
        stubConnectionCheck(aResponse().withStatus(204));

        // when
        edit("https://acme.example/directory");

        // then
        assertThat(loadMetadataValues(authority.getUuid().toString())).isEmpty();
    }

    @Test
    void keepsTheAttributesAndMetadata_whenTheConnectionCheckFails() throws Exception {
        // given
        var accountUrl = "https://acme.example/acct/1";
        var directoryUrl = "https://acme.example/directory";
        stubConnectionCheck(buildMetadataAnswer(buildMetadataJson(ACCOUNT_URL, accountUrl)));
        edit(directoryUrl);
        stubConnectionCheck(aResponse().withStatus(500));

        // when
        ThrowingCallable editWithFailingCheck = () -> edit("https://other.example/directory");

        // then
        assertThatThrownBy(editWithFailingCheck).isInstanceOf(ConnectorException.class);
        assertThat(loadDataAttributeValues(authority.getUuid().toString()))
                .containsExactly(Map.entry(DIRECTORY_URL, directoryUrl));
        assertThat(loadMetadataValues(authority.getUuid().toString()))
                .containsExactly(Map.entry(ACCOUNT_URL, accountUrl));
    }

    @Test
    void rollsBackTheAttributeUpdate_whenTheMetadataCannotBeStored() throws Exception {
        // given
        var directoryUrl = "https://acme.example/directory";
        var accountUrl = "https://acme.example/acct/1";
        stubConnectionCheck(buildMetadataAnswer(buildMetadataJson(ACCOUNT_URL, accountUrl) + ","
                + buildMetadataJson(KEY_THUMBPRINT, "old-thumbprint")));
        edit(directoryUrl);
        var metadataWithoutData = """
                {"version": 3, "uuid": "%s", "name": "%s", "type": "meta", "contentType": "string",
                 "content": [{"contentType": "string"}], "properties": {"label": "%s", "visible": true, "overwrite": true}}
                """
                .formatted(UUID.nameUUIDFromBytes(ACCOUNT_URL.getBytes()), ACCOUNT_URL, ACCOUNT_URL);
        stubConnectionCheck(buildMetadataAnswer(metadataWithoutData));

        // when
        ThrowingCallable editStoringMalformedMetadata = () -> edit("https://other.example/directory");

        // then
        assertThatThrownBy(editStoringMalformedMetadata).isInstanceOf(AttributeException.class);
        assertThat(loadDataAttributeValues(authority.getUuid().toString()))
                .containsExactly(Map.entry(DIRECTORY_URL, directoryUrl));
        assertThat(loadMetadataValues(authority.getUuid().toString()))
                .containsOnly(Map.entry(ACCOUNT_URL, accountUrl), Map.entry(KEY_THUMBPRINT, "old-thumbprint"));
    }

    @Test
    void leavesNoAuthorityBehind_whenTheMetadataOfANewAuthorityCannotBeStored() throws Exception {
        // given
        var metadataWithoutData = """
                {"version": 3, "uuid": "%s", "name": "%s", "type": "meta", "contentType": "string",
                 "content": [{"contentType": "string"}], "properties": {"label": "%s", "visible": true, "overwrite": true}}
                """
                .formatted(UUID.nameUUIDFromBytes(ACCOUNT_URL.getBytes()), ACCOUNT_URL, ACCOUNT_URL);
        stubConnectionCheck(buildMetadataAnswer(metadataWithoutData));
        var request = new AuthorityInstanceRequestDto();
        request.setName("rolled-back-v3-authority");
        request.setConnectorUuid(authority.getConnectorUuid().toString());
        request.setInterfaceUuid(authority.getConnectorInterfaceUuid());
        request.setAttributes(buildDirectoryUrlAttributes("https://acme.example/directory"));
        long authoritiesBefore = authorityInstanceReferenceRepository.count();
        long attributeMappingsBefore = attributeContent2ObjectRepository.count();

        // when
        ThrowingCallable createStoringMalformedMetadata = () -> authorityInstanceService
                .createAuthorityInstance(request);

        // then
        assertThatThrownBy(createStoringMalformedMetadata).isInstanceOf(AttributeException.class);
        assertThat(authorityInstanceReferenceRepository.count()).isEqualTo(authoritiesBefore);
        assertThat(attributeContent2ObjectRepository.count()).isEqualTo(attributeMappingsBefore);
    }

    @Test
    void showsTheMetadata_whenTheConnectorWasDeleted() throws Exception {
        // given
        var accountUrl = "https://acme.example/acct/1";
        stubConnectionCheck(buildMetadataAnswer(buildMetadataJson(ACCOUNT_URL, accountUrl)));
        edit("https://acme.example/directory");
        authority.setConnector(null);
        authority.setConnectorUuid(null);
        authorityInstanceReferenceRepository.save(authority);

        // when
        AuthorityInstanceDto detail = authorityInstanceService.getAuthorityInstance(authority.getSecuredUuid());

        // then
        assertThat(detail.getConnectorName()).endsWith("(Deleted)");
        assertThat(extractMetadataValues(detail.getMetadata())).containsExactly(Map.entry(ACCOUNT_URL, accountUrl));
    }

    @Test
    void removesTheMetadata_whenTheAuthorityIsDeleted() throws Exception {
        // given
        stubConnectionCheck(buildMetadataAnswer(buildMetadataJson(ACCOUNT_URL, "https://acme.example/acct/1")));
        edit("https://acme.example/directory");

        // when
        authorityInstanceService.deleteAuthorityInstance(authority.getSecuredUuid());

        // then
        assertThat(attributeContent2ObjectRepository
                .findByObjectTypeAndObjectUuid(Resource.AUTHORITY, authority.getUuid())).isEmpty();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void stubConnectionCheck(ResponseDefinitionBuilder answer) {
        wireMockServer.stubFor(post(urlEqualTo(CONNECTION_PATH)).willReturn(answer));
    }

    private void edit(String directoryUrl) throws Exception {
        var request = new AuthorityInstanceUpdateRequestDto();
        request.setAttributes(buildDirectoryUrlAttributes(directoryUrl));
        authorityInstanceService.editAuthorityInstance(authority.getSecuredUuid(), request);
    }

    private Map<String, Object> loadMetadataValues(String authorityUuid) throws Exception {
        return extractMetadataValues(
                authorityInstanceService.getAuthorityInstance(SecuredUUID.fromString(authorityUuid)).getMetadata());
    }

    private Map<String, Object> loadDataAttributeValues(String authorityUuid) throws Exception {
        Map<String, Object> values = new LinkedHashMap<>();
        for (ResponseAttribute attribute : authorityInstanceService
                .getAuthorityInstance(SecuredUUID.fromString(authorityUuid))
                .getAttributes()) {
            List<AttributeContent> content = attribute.getContent();
            values.put(attribute.getName(), content.getFirst().getData());
        }
        return values;
    }

    private static Map<String, Object> extractMetadataValues(List<MetadataResponseDto> metadata) {
        Map<String, Object> values = new LinkedHashMap<>();
        for (MetadataResponseDto group : metadata) {
            for (ResponseMetadata item : group.getItems()) {
                values.put(item.getName(), item.getContent().getFirst().getData());
            }
        }
        return values;
    }

    private static List<RequestAttribute> buildDirectoryUrlAttributes(String directoryUrl) {
        return List
                .of(aCustomAttribute()
                        .withUuid(DIRECTORY_URL_UUID)
                        .withName(DIRECTORY_URL)
                        .withStringContent(directoryUrl)
                        .build());
    }

    private static ResponseDefinitionBuilder buildMetadataAnswer(String metadataItems) {
        return WireMock.okJson("{\"metadata\": [" + metadataItems + "]}");
    }

    private static String buildMetadataJson(String name, String value) {
        return """
                {"version": 3, "uuid": "%s", "name": "%s", "type": "meta", "contentType": "string",
                 "content": [{"contentType": "string", "data": "%s"}], "properties": {"label": "%s", "visible": true, "overwrite": true}}
                """
                .formatted(UUID.nameUUIDFromBytes(name.getBytes()), name, value, name);
    }
}

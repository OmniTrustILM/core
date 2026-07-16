package com.otilm.core.integration.service;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateRegistrationDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.AttributeExternalService;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.authority.AdapterOperationResult;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.service.handler.authority.RegisterCapability;
import com.otilm.core.service.v2.ClientOperationExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.List;
import java.util.UUID;

import static com.otilm.core.util.builders.RequestAttributeV3Builder.aCustomAttribute;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Exercises the real {@link AttributeEngine} (definition + relation persisted in the DB) rather than a mocked
 * one, so it actually proves the pre-registration custom-attribute content survives a round trip — unlike
 * {@link ClientOperationServiceRegisterITest#registerValidatesAndPersistsCustomAttributes()}, which mocks
 * {@code AttributeEngine} and only verifies the call was made with the right arguments.
 */
@SpringBootTest
class ClientOperationServiceRegisterCustomAttributeITest extends BaseSpringBootTest {

    @Autowired
    private ClientOperationExternalService clientOperationService;
    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private AttributeExternalService attributeService;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private CertificateRepository certificateRepository;

    @MockitoBean
    private AuthorityProviderAdapterFactory adapterFactory;
    @MockitoBean
    private ConnectorCapabilityService capabilityService;
    @MockitoBean
    private ActionProducer actionProducer;
    @MockitoBean
    private EventProducer eventProducer;

    private RaProfile raProfile;
    private SecuredParentUUID authorityParent;
    private SecuredUUID securedRaProfile;

    @BeforeEach
    void setUpRegistrationFixtures() {
        Connector connector = new Connector();
        connector.setUrl("http://localhost");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setAuthorityInstanceUuid("1");
        authority.setConnector(connector);
        authority = authorityInstanceReferenceRepository.save(authority);

        raProfile = new RaProfile();
        raProfile.setName("registerCustomAttributeRaProfile");
        raProfile.setAuthorityInstanceReference(authority);
        raProfile.setAuthorityInstanceReferenceUuid(authority.getUuid());
        raProfile.setEnabled(true);
        raProfile = raProfileRepository.save(raProfile);
        authorityParent = SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid());
        securedRaProfile = raProfile.getSecuredUuid();

        when(capabilityService.supports(Mockito.any(AuthorityInstanceReference.class), Mockito.any()))
                .thenReturn(true);
    }

    private RequestAttributeV3 createCertificateCustomAttribute(String name, String value) throws Exception {
        CustomAttributeCreateRequestDto createRequest = new CustomAttributeCreateRequestDto();
        createRequest.setName(name);
        createRequest.setLabel(name);
        createRequest.setResources(List.of(Resource.CERTIFICATE));
        createRequest.setContentType(AttributeContentType.STRING);
        String attributeUuid = attributeService.createCustomAttribute(createRequest).getUuid();
        return aCustomAttribute()
                .withUuid(attributeUuid)
                .withName(name)
                .withStringContent(value)
                .build();
    }

    @Test
    void registerPersistsCustomAttributeContentInTheRealAttributeEngine() throws Exception {
        // Real AttributeEngine + a real custom attribute definition (not mocked): proves the value is actually
        // written to (and retrievable from) the attribute-content tables, not merely that the call was made.
        RequestAttributeV3 requestAttribute = createCertificateCustomAttribute("registerCustomAttr", "device-1-owner");

        AuthorityProviderAdapter adapter = mock(AuthorityProviderAdapter.class,
                Mockito.withSettings().extraInterfaces(RegisterCapability.class));
        when(adapterFactory.forAuthority(Mockito.any())).thenReturn(adapter);
        when(((RegisterCapability) adapter).register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));

        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setSubjectDn("CN=device-1,O=Acme");
        request.setCustomAttributes(List.of(requestAttribute));

        ClientCertificateDataResponseDto response = clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request);

        UUID certUuid = UUID.fromString(response.getUuid());
        List<ResponseAttribute> persisted = attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, certUuid);
        Assertions.assertEquals(1, persisted.size(), "exactly the one submitted custom attribute must be persisted");
        ResponseAttributeV3 persistedAttribute = (ResponseAttributeV3) persisted.getFirst();
        Assertions.assertEquals("registerCustomAttr", persistedAttribute.getName());
        Assertions.assertEquals("device-1-owner",
                ((StringAttributeContentV3) persistedAttribute.getContent().getFirst()).getData(),
                "the submitted value must round-trip through the real attribute engine");
    }

    @Test
    void registerRejectsInvalidCustomAttributesBeforeCreatingPlaceholder() {
        // Real engine, genuinely invalid content (no definition/relation backs this attribute name for
        // Resource.CERTIFICATE) — proves validateCustomAttributesContent is consulted for real and rejects
        // up front, before the placeholder certificate is created. No adapter stubbing needed: the request
        // never gets that far.
        RequestAttributeV3 undefinedAttribute = aCustomAttribute()
                .withUuid(UUID.randomUUID())
                .withName("attributeWithNoDefinition")
                .withStringContent("some-value")
                .build();
        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setSubjectDn("CN=device-1,O=Acme");
        request.setCustomAttributes(List.of(undefinedAttribute));

        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request));

        List<Certificate> certs = certificateRepository.findAll();
        Assertions.assertTrue(certs.isEmpty(),
                "an up-front custom-attribute validation failure must leave no placeholder certificate behind");
    }
}

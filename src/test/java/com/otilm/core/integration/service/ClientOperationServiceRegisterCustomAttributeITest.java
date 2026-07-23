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
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRegistrationDto;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.mapping.FieldType;
import com.otilm.api.model.common.attribute.v3.mapping.RdnMappedField;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.raprofile.AttributeSetMergeMode;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.writer.RaProfileCertificateRequestAttributeWriter;
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
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static com.otilm.core.util.builders.MappedDataAttributeV3Builder.aMappedDataAttribute;
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
    @Autowired
    private CertificateExternalService certificateExternalService;
    @Autowired
    private RaProfileCertificateRequestAttributeWriter requestAttributeWriter;
    @Autowired
    private com.fasterxml.jackson.databind.ObjectMapper objectMapper;

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
    void registerPlatformLevelPersistsCustomAttributeContentInTheRealAttributeEngine() throws Exception {
        // Same real-engine round-trip proof, but on the platform-level path (adapter without RegisterCapability,
        // so registerCertificate falls back to registerPlatformLevel) — covers the second call site that
        // persists custom attributes, not just the connector-backed one above.
        RequestAttributeV3 requestAttribute = createCertificateCustomAttribute("registerPlatformCustomAttr", "device-2-owner");
        when(adapterFactory.forAuthority(Mockito.any())).thenReturn(mock(AuthorityProviderAdapter.class));

        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setSubjectDn("CN=device-2,O=Acme");
        request.setCustomAttributes(List.of(requestAttribute));

        ClientCertificateDataResponseDto response = clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request);

        UUID certUuid = UUID.fromString(response.getUuid());
        List<ResponseAttribute> persisted = attributeEngine.getObjectCustomAttributesContent(Resource.CERTIFICATE, certUuid);
        Assertions.assertEquals(1, persisted.size(), "exactly the one submitted custom attribute must be persisted");
        ResponseAttributeV3 persistedAttribute = (ResponseAttributeV3) persisted.getFirst();
        Assertions.assertEquals("registerPlatformCustomAttr", persistedAttribute.getName());
        Assertions.assertEquals("device-2-owner",
                ((StringAttributeContentV3) persistedAttribute.getContent().getFirst()).getData(),
                "the submitted value must round-trip through the real attribute engine on the platform-level path");
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

    @Test
    void registerPersistsRequestAttributeValuesVisibleOnTheCertificateDetail() throws Exception {
        // Author an RA-profile request attribute mapping the CN RDN, so the real resolver returns it and the
        // submitted value projects to the placeholder identity and is persisted as a registration request attribute.
        DataAttributeV3 cnDef = aMappedDataAttribute().withName("commonName").mappingRdn("2.5.4.3").build();
        // fieldType is the serialized type discriminator for MappedField; the builder leaves it unset, so set it
        // here or the RA-profile set can't be deserialized back by the real resolver.
        ((RdnMappedField) cnDef.getFieldMapping().getFields().getFirst()).setFieldType(FieldType.RDN);
        UUID cnUuid = UUID.randomUUID();
        cnDef.setUuid(cnUuid.toString());
        requestAttributeWriter.saveStaticSet(raProfile,
                objectMapper.writeValueAsString(List.of(cnDef)), AttributeSetMergeMode.STATIC_ONLY, null);

        AuthorityProviderAdapter adapter = mock(AuthorityProviderAdapter.class,
                Mockito.withSettings().extraInterfaces(RegisterCapability.class));
        when(adapterFactory.forAuthority(Mockito.any())).thenReturn(adapter);
        when(((RegisterCapability) adapter).register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));

        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setCsrAttributes(List.of(new RequestAttributeV3(cnUuid, "commonName",
                AttributeContentType.STRING, List.<BaseAttributeContentV3<?>>of(new StringAttributeContentV3("device-rt")))));

        ClientCertificateDataResponseDto response = clientOperationService.registerCertificate(
                authorityParent, securedRaProfile, request);

        CertificateDetailDto detail = certificateExternalService.getCertificate(SecuredUUID.fromString(response.getUuid()));
        List<ResponseAttribute> persisted = detail.getRegistrationRequestAttributes();
        Assertions.assertEquals(1, persisted.size(), "the submitted request attribute must round-trip to the certificate detail");
        ResponseAttributeV3 attr = (ResponseAttributeV3) persisted.getFirst();
        Assertions.assertEquals("commonName", attr.getName());
        Assertions.assertEquals("device-rt",
                ((StringAttributeContentV3) attr.getContent().getFirst()).getData(),
                "the submitted registration request-attribute value must be readable from the detail");
    }

    @Test
    void completionPersistsRequestAttributeValuesOnTheRequestEntity() throws Exception {
        // Author the CN request attribute so the completion can resolve + validate it.
        DataAttributeV3 cnDef = aMappedDataAttribute().withName("commonName").mappingRdn("2.5.4.3").build();
        ((RdnMappedField) cnDef.getFieldMapping().getFields().getFirst()).setFieldType(FieldType.RDN);
        UUID cnUuid = UUID.randomUUID();
        cnDef.setUuid(cnUuid.toString());
        requestAttributeWriter.saveStaticSet(raProfile,
                objectMapper.writeValueAsString(List.of(cnDef)), AttributeSetMergeMode.STATIC_ONLY, null);

        // Register a flat placeholder (no csrAttributes → no registrationRequestAttributes), then complete it with a
        // CSR carrying request attributes; the completion values are persisted on the request entity.
        AuthorityProviderAdapter adapter = mock(AuthorityProviderAdapter.class,
                Mockito.withSettings().extraInterfaces(RegisterCapability.class));
        when(adapterFactory.forAuthority(Mockito.any())).thenReturn(adapter);
        when(((RegisterCapability) adapter).register(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(AdapterOperationResult.syncOk(null, null, CertificateType.X509));
        ClientCertificateRegistrationDto registration = new ClientCertificateRegistrationDto();
        registration.setSubjectDn("CN=device-complete,O=Acme");
        String certUuid = clientOperationService.registerCertificate(authorityParent, securedRaProfile, registration).getUuid();

        ClientCertificateIssueRequestDto completion = new ClientCertificateIssueRequestDto();
        completion.setRequest(generateCsrBase64());
        completion.setFormat(CertificateRequestFormat.PKCS10);
        completion.setCsrAttributes(List.of(new RequestAttributeV3(cnUuid, "commonName",
                AttributeContentType.STRING, List.<BaseAttributeContentV3<?>>of(new StringAttributeContentV3("device-complete")))));
        clientOperationService.issueExistingCertificate(authorityParent, securedRaProfile, certUuid, completion);

        CertificateDetailDto detail = certificateExternalService.getCertificate(SecuredUUID.fromString(certUuid));
        List<ResponseAttribute> reqAttrs = detail.getCertificateRequest().getAttributes();
        Assertions.assertEquals(1, reqAttrs.size(), "the completion request attribute must be persisted on the request entity");
        Assertions.assertEquals("device-complete",
                ((StringAttributeContentV3) ((ResponseAttributeV3) reqAttrs.getFirst()).getContent().getFirst()).getData(),
                "the completion request-attribute value must be readable from the detail");
    }

    private String generateCsrBase64() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=device-complete,O=Acme"), keyPair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate()));
        return Base64.getEncoder().encodeToString(csr.getEncoded());
    }
}

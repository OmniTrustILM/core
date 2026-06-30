package com.otilm.core.service;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.enums.cryptography.*;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.v2.ClientCertificateRequestDto;
import com.otilm.core.attribute.CsrAttributes;
import com.otilm.core.attribute.RsaSignatureAttributes;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.dao.entity.*;
import com.otilm.core.dao.repository.*;
import com.otilm.core.service.v2.ClientOperationService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.MetaDefinitions;
import com.otilm.core.util.seeders.CryptographicKeySeeder;
import com.otilm.core.util.seeders.FunctionGroupSeeder;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.*;
import java.util.*;

import static com.otilm.core.util.builders.RequestAttributeV3Builder.aCustomAttribute;
import static com.otilm.core.util.builders.RsaSignatureAttributesBuilder.rsaSignatureAttributes;
import static com.otilm.core.util.seeders.CryptographicKeySeeder.KeyItemSpec.signingPrivateKey;
import static com.otilm.core.util.seeders.CryptographicKeySeeder.KeyItemSpec.verifyingPublicKey;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
class CertificateRequestIntegrationTest extends BaseSpringBootTest {

    // Custom OID used for the extension-mapped attribute in the projection test below.
    private static final String CUSTOM_EXT_OID = "1.2.3.4.5";
    private static final String SAN_ATTR_UUID = "aaaaaaaa-0000-0000-0000-000000000001";
    private static final String EXT_ATTR_UUID = "bbbbbbbb-0000-0000-0000-000000000002";

    @Autowired
    private ClientOperationService clientOperationService;

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private FunctionGroupSeeder functionGroupSeeder;

    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;

    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    @Autowired
    private CryptographicKeySeeder cryptographicKeySeeder;

    private WireMockServer mockServer;
    private RaProfile raProfile;
    private TokenProfile tokenProfile;
    private CryptographicKey cryptographicKey;
    private KeyPair keyPair;

    @BeforeEach
    void wireConnectorRaProfileAndCryptographicKey() throws NoSuchAlgorithmException, AttributeException {
        mockServer = new WireMockServer(0);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        // Single connector serves both the authority and the crypto provider — WireMock
        // routes by path, so one URL+version is sufficient for both function groups.
        Connector connector = new Connector();
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
        iface.setConnectorUuid(connector.getUuid());
        iface.setInterfaceCode(ConnectorInterface.AUTHORITY);
        iface.setVersion("v3");
        iface = connectorInterfaceRepository.save(iface);

        AuthorityInstanceReference authorityRef = new AuthorityInstanceReference();
        authorityRef.setAuthorityInstanceUuid("authority-instance-1");
        authorityRef.setConnector(connector);
        authorityRef.setConnectorInterface(iface);
        authorityRef = authorityInstanceReferenceRepository.save(authorityRef);

        raProfile = new RaProfile();
        raProfile.setName("modeATestRaProfile");
        raProfile.setAuthorityInstanceReference(authorityRef);
        raProfile.setAuthorityInstanceReferenceUuid(authorityRef.getUuid());
        raProfile.setEnabled(true);
        raProfile = raProfileRepository.save(raProfile);

        FunctionGroup functionGroup = functionGroupSeeder.seed(FunctionGroupCode.CRYPTOGRAPHY_PROVIDER, List.of());

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setConnectorUuid(connector.getUuid());
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setFunctionGroupUuid(functionGroup.getUuid());
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("Soft")));
        connector2FunctionGroupRepository.save(c2fg);

        TokenInstanceReference tokenInstanceReference = new TokenInstanceReference();
        tokenInstanceReference.setName("modeATokenInstance");
        tokenInstanceReference.setConnector(connector);
        tokenInstanceReference.setConnectorUuid(connector.getUuid());
        tokenInstanceReference.setKind("sample");
        tokenInstanceReference.setTokenInstanceUuid("22222222-2222-2222-2222-222222222222");
        tokenInstanceReferenceRepository.save(tokenInstanceReference);

        tokenProfile = new TokenProfile();
        tokenProfile.setName("modeATokenProfile");
        tokenProfile.setTokenInstanceReference(tokenInstanceReference);
        tokenProfile.setDescription("mode A test token profile");
        tokenProfile.setEnabled(true);
        tokenProfile.setTokenInstanceName("modeATokenInstance");
        tokenProfileRepository.save(tokenProfile);

        // truncateTables() in BaseSpringBootTest wipes all rows including attribute definitions
        // that ContextRefreshListener registers at startup. Re-seed them here exactly as the
        // listener does: connectorUuid=null, operation="sign".
        attributeEngine.updateDataAttributeDefinitions(null, AttributeOperation.SIGN,
                RsaSignatureAttributes.getRsaSignatureAttributes());

        keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        var publicKeyData = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        cryptographicKey = cryptographicKeySeeder.seedKey("modeATestKey", tokenProfile, tokenInstanceReference,
                signingPrivateKey(KeyAlgorithm.RSA).withMaterial(KeyFormat.PRKI, "placeholder"),
                verifyingPublicKey(KeyAlgorithm.RSA).withMaterial(KeyFormat.SPKI, publicKeyData));
    }

    @AfterEach
    void stopMockServer() {
        mockServer.stop();
    }

    @Test
    void projectsConnectorSanAndExtensionIntoStoredCsr_whenSubmittingRequest() throws Exception {
        // given a connector that returns one SAN-mapped and one extension-mapped attribute, with the
        // default relative-distinguished-name set merged in by the issuance-definition resolver
        String connectorAttrsJson = """
                [
                  {
                    "uuid": "%s",
                    "name": "sanDns",
                    "description": "DNS SAN",
                    "type": "data",
                    "version": 3,
                    "contentType": "string",
                    "properties": {"label": "DNS SAN", "required": false, "readOnly": false,
                                   "visible": true, "list": false, "multiSelect": false},
                    "fieldMapping": {
                      "objectType": "x509Certificate",
                      "fields": [{"fieldType": "san", "generalNameType": "dns"}]
                    }
                  },
                  {
                    "uuid": "%s",
                    "name": "customExt",
                    "description": "Custom extension",
                    "type": "data",
                    "version": 3,
                    "contentType": "string",
                    "properties": {"label": "Custom Extension", "required": false, "readOnly": false,
                                   "visible": true, "list": false, "multiSelect": false},
                    "fieldMapping": {
                      "objectType": "x509Certificate",
                      "fields": [{"fieldType": "extension", "extensionOid": "%s"}]
                    }
                  }
                ]
                """.formatted(SAN_ATTR_UUID, EXT_ATTR_UUID, CUSTOM_EXT_OID);
        stubIssueAttributes(connectorAttrsJson);
        stubSigning();

        // Extension value: DER-encoded UTF8String "modeAExtValue", then base64 for transport.
        var extValueBase64 = Base64.getEncoder().encodeToString(new DERUTF8String("modeAExtValue").getEncoded());
        var request = baseRequest();
        request.setCsrAttributes(List.of(
                commonNameAttribute("ModeATest"),
                aCustomAttribute().withUuid(SAN_ATTR_UUID).withName("sanDns")
                        .withStringContent("connector.example.com").build(),
                aCustomAttribute().withUuid(EXT_ATTR_UUID).withName("customExt")
                        .withStringContent(extValueBase64).build()));

        // when
        CertificateDetailDto result = clientOperationService.submitCertificateRequest(request, null);

        // then
        assertThat(result).isNotNull();
        assertThat(result.getSubjectDn()).contains("CN=ModeATest");
        assertThat(result.getCertificateRequest()).isNotNull();

        Extensions storedExts = extensionsOfStoredCsr(result);
        assertThat(storedExts.getExtension(Extension.subjectAlternativeName))
                .as("stored CSR should carry the connector-supplied SAN")
                .isNotNull();
        assertThat(storedExts.getExtension(new ASN1ObjectIdentifier(CUSTOM_EXT_OID)))
                .as("stored CSR should carry the connector-supplied extension-mapped attribute")
                .isNotNull();
    }

    @Test
    void failsRequest_whenConnectorAttributeFetchFails() throws Exception {
        // given — the v3 connector issue-attributes endpoint errors. resolveIssuanceDefinitions fails on a genuine connector
        // failure rather than silently falling back to the default CSR set, so the request is rejected.
        stubIssueAttributes("[]");
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v3/authorityProvider/certificates/issue/attributes"))
                .willReturn(WireMock.serverError().withBody("issue-attributes endpoint is unavailable")));
        stubSigning();

        var request = baseRequest();
        request.setCsrAttributes(List.of(commonNameAttribute("FailClosed")));

        // when / then
        assertThatThrownBy(() -> clientOperationService.submitCertificateRequest(request, null))
                .isInstanceOf(ConnectorException.class);
    }

    @Test
    void throwsValidation_whenRaProfileNotSpecified() {
        // given — a key-backed request with no RA profile UUID
        var request = baseRequest();
        request.setRaProfileUuid(null);
        request.setCsrAttributes(List.of(commonNameAttribute("NoRaProfile")));

        // when / then
        assertThatThrownBy(() -> clientOperationService.submitCertificateRequest(request, null))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("RA profile");
    }

    @Test
    void throwsValidation_whenRaProfileUuidIsUnknown() {
        // given — a request pointing at an RA profile that does not exist
        var request = baseRequest();
        request.setRaProfileUuid(UUID.randomUUID());
        request.setCsrAttributes(List.of(commonNameAttribute("UnknownRaProfile")));

        // when / then
        assertThatThrownBy(() -> clientOperationService.submitCertificateRequest(request, null))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("RA profile");
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private void stubIssueAttributes(String connectorAttrsJson) {
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v3/authorityProvider/certificates/issue/attributes"))
                .willReturn(WireMock.okJson(connectorAttrsJson)));
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
    }

    /**
     * Stubs the crypto provider's sign/verify endpoints. The signature is produced with the real
     * private key so it verifies against the stored public key; the token connector passes the
     * value through without independent verification here.
     */
    private void stubSigning() throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(keyPair.getPrivate());
        sig.update(keyPair.getPublic().getEncoded());
        var signature = Base64.getEncoder().encodeToString(sig.sign());

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/sign"))
                .willReturn(WireMock.okJson("""
                        {"signatures": [{"data": "%s"}]}
                        """.formatted(signature))));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/verify"))
                .willReturn(WireMock.okJson("""
                        {"verifications": [{"result": true}]}
                        """)));
    }

    private ClientCertificateRequestDto baseRequest() {
        ClientCertificateRequestDto request = new ClientCertificateRequestDto();
        request.setRaProfileUuid(raProfile.getUuid());
        request.setFormat(CertificateRequestFormat.PKCS10);
        request.setKeyUuid(cryptographicKey.getUuid());
        request.setTokenProfileUuid(tokenProfile.getUuid());
        request.setSignatureAttributes(rsaSignatureAttributes().build());
        return request;
    }

    private static RequestAttributeV3 commonNameAttribute(String value) {
        return aCustomAttribute()
                .withUuid(CsrAttributes.COMMON_NAME_UUID)
                .withName(CsrAttributes.COMMON_NAME_ATTRIBUTE_NAME)
                .withStringContent(value)
                .build();
    }

    private static Extensions extensionsOfStoredCsr(CertificateDetailDto result) throws Exception {
        byte[] storedDer = Base64.getDecoder().decode(result.getCertificateRequest().getContent());
        PKCS10CertificationRequest storedCsr = new PKCS10CertificationRequest(storedDer);
        Attribute[] extAttrs = storedCsr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        assertThat(extAttrs).as("stored CSR should carry an extension request attribute").isNotEmpty();
        return Extensions.getInstance(extAttrs[0].getAttrValues().getObjectAt(0));
    }
}

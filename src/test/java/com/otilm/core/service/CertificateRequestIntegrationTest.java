package com.otilm.core.service;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.*;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
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
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import org.bouncycastle.asn1.DERUTF8String;

import java.security.*;
import java.util.*;

@SpringBootTest
class CertificateRequestIntegrationTest extends BaseSpringBootTest {

    @Autowired
    private ClientOperationService clientOperationService;

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private FunctionGroupRepository functionGroupRepository;

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
    private CryptographicKeyRepository cryptographicKeyRepository;

    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;

    private WireMockServer mockServer;
    private RaProfile raProfile;
    private TokenProfile tokenProfile;
    private CryptographicKey cryptographicKey;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException, com.otilm.api.exception.AttributeException {
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

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.CRYPTOGRAPHY_PROVIDER);
        functionGroup.setName(FunctionGroupCode.CRYPTOGRAPHY_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

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
        cryptographicKey = new CryptographicKey();
        cryptographicKey.setName("modeATestKey");
        cryptographicKey.setTokenProfile(tokenProfile);
        cryptographicKey.setTokenInstanceReference(tokenInstanceReference);
        cryptographicKeyRepository.save(cryptographicKey);

        CryptographicKeyItem privateKeyItem = new CryptographicKeyItem();
        privateKeyItem.setLength(2048);
        privateKeyItem.setKey(cryptographicKey);
        privateKeyItem.setKeyUuid(cryptographicKey.getUuid());
        privateKeyItem.setType(KeyType.PRIVATE_KEY);
        privateKeyItem.setKeyData("placeholder");
        privateKeyItem.setFormat(KeyFormat.PRKI);
        privateKeyItem.setState(KeyState.ACTIVE);
        privateKeyItem.setEnabled(true);
        privateKeyItem.setKeyAlgorithm(KeyAlgorithm.RSA);
        privateKeyItem.setKeyReferenceUuid(UUID.randomUUID());
        privateKeyItem.setUsage(List.of(KeyUsage.SIGN));
        cryptographicKeyItemRepository.save(privateKeyItem);
        privateKeyItem.setKeyReferenceUuid(privateKeyItem.getUuid());
        cryptographicKeyItemRepository.save(privateKeyItem);

        CryptographicKeyItem publicKeyItem = new CryptographicKeyItem();
        publicKeyItem.setLength(2048);
        publicKeyItem.setKey(cryptographicKey);
        publicKeyItem.setKeyUuid(cryptographicKey.getUuid());
        publicKeyItem.setType(KeyType.PUBLIC_KEY);
        publicKeyItem.setKeyData(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        publicKeyItem.setFormat(KeyFormat.SPKI);
        publicKeyItem.setState(KeyState.ACTIVE);
        publicKeyItem.setEnabled(true);
        publicKeyItem.setKeyAlgorithm(KeyAlgorithm.RSA);
        publicKeyItem.setKeyReferenceUuid(UUID.randomUUID());
        publicKeyItem.setUsage(List.of(KeyUsage.VERIFY));
        cryptographicKeyItemRepository.save(publicKeyItem);
        publicKeyItem.setKeyReferenceUuid(publicKeyItem.getUuid());
        cryptographicKeyItemRepository.save(publicKeyItem);

        Set<CryptographicKeyItem> items = new HashSet<>();
        items.add(privateKeyItem);
        items.add(publicKeyItem);
        cryptographicKey.setItems(items);
        cryptographicKeyRepository.save(cryptographicKey);
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    // Custom OID used for the extension-mapped attribute in the test below.
    private static final String CUSTOM_EXT_OID = "1.2.3.4.5";

    @Test
    void submitCertificateRequest_rdnAndSanProjectedFromConnectorAndDefaultAttributes() throws Exception {
        // Connector returns two DataAttributeV3: one with a SAN DNS field mapping and one with
        // an extension field mapping (custom OID). The default RDN set (CN, OU, O, L, ST, C) is
        // merged in by resolveIssuanceDefinitions.
        String connectorAttrsJson = """
                [
                  {
                    "uuid": "aaaaaaaa-0000-0000-0000-000000000001",
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
                    "uuid": "bbbbbbbb-0000-0000-0000-000000000002",
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
                """.formatted(CUSTOM_EXT_OID);
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v3/authorityProvider/certificates/issue/attributes"))
                .willReturn(WireMock.okJson(connectorAttrsJson)));
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        // The crypto service calls the token connector to sign the CSR data; the token
        // connector is also WireMock-backed. The signature is produced with the real private key
        // so it verifies correctly against the stored public key.
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(keyPair.getPrivate());
        // The actual data to sign is determined by the CSR builder internally; we return a
        // signature over the public key bytes as a stand-in — the token connector is mocked
        // and the signature value is passed through without independent verification here.
        sig.update(keyPair.getPublic().getEncoded());
        String signature = Base64.getEncoder().encodeToString(sig.sign());

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

        List<RequestAttribute> signatureAttributes = List.of(
                RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5),
                RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA_256));

        RequestAttributeV3 cnAttr = new RequestAttributeV3(
                UUID.fromString(CsrAttributes.COMMON_NAME_UUID),
                CsrAttributes.COMMON_NAME_ATTRIBUTE_NAME,
                AttributeContentType.STRING,
                List.of(new StringAttributeContentV3("ModeATest")));

        RequestAttributeV3 sanAttr = new RequestAttributeV3(
                UUID.fromString("aaaaaaaa-0000-0000-0000-000000000001"),
                "sanDns",
                AttributeContentType.STRING,
                List.of(new StringAttributeContentV3("connector.example.com")));

        // Extension value: DER-encoded UTF8String "modeAExtValue", then base64 for transport.
        String extValueBase64 = Base64.getEncoder().encodeToString(
                new DERUTF8String("modeAExtValue").getEncoded());
        RequestAttributeV3 extAttr = new RequestAttributeV3(
                UUID.fromString("bbbbbbbb-0000-0000-0000-000000000002"),
                "customExt",
                AttributeContentType.STRING,
                List.of(new StringAttributeContentV3(extValueBase64)));

        ClientCertificateRequestDto request = new ClientCertificateRequestDto();
        request.setRaProfileUuid(raProfile.getUuid());
        request.setFormat(CertificateRequestFormat.PKCS10);
        request.setKeyUuid(cryptographicKey.getUuid());
        request.setTokenProfileUuid(tokenProfile.getUuid());
        request.setCsrAttributes(List.of(cnAttr, sanAttr, extAttr));
        request.setSignatureAttributes(signatureAttributes);

        CertificateDetailDto result = clientOperationService.submitCertificateRequest(request, null);

        Assertions.assertNotNull(result);
        Assertions.assertTrue(result.getSubjectDn().contains("CN=ModeATest"),
                "Subject DN should contain CN from csrAttributes, got: " + result.getSubjectDn());

        Assertions.assertNotNull(result.getCertificateRequest());
        byte[] storedDer = Base64.getDecoder().decode(result.getCertificateRequest().getContent());
        PKCS10CertificationRequest storedCsr = new PKCS10CertificationRequest(storedDer);
        org.bouncycastle.asn1.pkcs.Attribute[] extAttrs =
                storedCsr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        Assertions.assertNotNull(extAttrs, "Stored CSR should carry an extension request attribute");
        Extensions storedExts = Extensions.getInstance(extAttrs[0].getAttrValues().getObjectAt(0));
        Assertions.assertNotNull(storedExts.getExtension(Extension.subjectAlternativeName),
                "Stored CSR should contain subjectAlternativeName from connector-supplied SAN attribute");
        Assertions.assertNotNull(
                storedExts.getExtension(new org.bouncycastle.asn1.ASN1ObjectIdentifier(CUSTOM_EXT_OID)),
                "Stored CSR should contain custom extension from connector-supplied extension-mapped attribute");
    }
}

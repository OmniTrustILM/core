package com.czertainly.core.service;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.RequestAttributeV3;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.client.cryptography.operations.*;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.czertainly.api.model.common.enums.cryptography.*;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.cryptography.key.KeyState;
import com.czertainly.api.model.core.cryptography.key.KeyUsage;
import com.czertainly.api.model.core.enums.CertificateRequestFormat;
import com.czertainly.core.attribute.RsaSignatureAttributes;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.model.request.CertificateRequest;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.CertificateRequestUtils;
import com.czertainly.core.util.MetaDefinitions;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jcajce.interfaces.SLHDSAPublicKey;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

class CryptographicOperationServiceTest extends BaseSpringBootTest {

    @Autowired
    private CryptographicOperationService cryptographicOperationService;

    @Autowired
    private TokenInstanceService tokenInstanceService;

    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private FunctionGroupRepository functionGroupRepository;

    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;

    private TokenInstanceReference tokenInstanceReference;
    private TokenProfile tokenProfile;
    private CryptographicKeyItem content1;
    private CryptographicKey key;
    private WireMockServer mockServer;

    @BeforeEach
    public void setUp() {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        Connector connector = new Connector();
        connector.setName("tokenInstanceConnector");
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

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

        connector.getFunctionGroups().add(c2fg);
        connectorRepository.save(connector);

        tokenInstanceReference = new TokenInstanceReference();
        tokenInstanceReference.setName("testInstance");
        tokenInstanceReference.setConnector(connector);
        tokenInstanceReference.setConnectorUuid(connector.getUuid());
        tokenInstanceReference.setKind("sample");
        tokenInstanceReference.setTokenInstanceUuid("11111111-1111-1111-1111-111111111111");
        tokenInstanceReferenceRepository.save(tokenInstanceReference);

        tokenProfile = new TokenProfile();
        tokenProfile.setName("profile1");
        tokenProfile.setTokenInstanceReference(tokenInstanceReference);
        tokenProfile.setDescription("sample description");
        tokenProfile.setEnabled(true);
        tokenProfile.setTokenInstanceName("testInstance");
        tokenProfileRepository.save(tokenProfile);

        key = createAndSaveKey("testKey1", KeyAlgorithm.RSA, "some/encrypted/data");
    }

    private CryptographicKey createAndSaveKey(String name, KeyAlgorithm keyAlgorithm, String publicKeyData) {
        CryptographicKey cryptographicKey = new CryptographicKey();
        cryptographicKey.setName(name);
        cryptographicKey.setDescription("sampleDescription");
        cryptographicKey.setTokenProfile(tokenProfile);
        cryptographicKey.setTokenInstanceReference(tokenInstanceReference);
        cryptographicKeyRepository.save(cryptographicKey);

        CryptographicKeyItem content = new CryptographicKeyItem();
        content.setLength(1024);
        content.setKey(cryptographicKey);
        content.setKeyUuid(cryptographicKey.getUuid());
        content.setType(KeyType.PRIVATE_KEY);
        content.setKeyData("some/encrypted/data");
        content.setFormat(KeyFormat.PRKI);
        content.setState(KeyState.ACTIVE);
        content.setEnabled(true);
        content.setKeyAlgorithm(keyAlgorithm);
        content.setKeyReferenceUuid(UUID.randomUUID());
        content.setUsage(List.of(KeyUsage.SIGN, KeyUsage.ENCRYPT, KeyUsage.VERIFY, KeyUsage.DECRYPT));
        cryptographicKeyItemRepository.save(content);

        content1 = new CryptographicKeyItem();
        content1.setLength(1024);
        content1.setKey(cryptographicKey);
        content1.setKeyUuid(cryptographicKey.getUuid());
        content1.setType(KeyType.PUBLIC_KEY);
        content1.setKeyData(publicKeyData);
        content1.setFormat(KeyFormat.SPKI);
        content1.setState(KeyState.ACTIVE);
        content1.setEnabled(true);
        content1.setKeyAlgorithm(keyAlgorithm);
        content1.setKeyReferenceUuid(UUID.randomUUID());
        content1.setUsage(List.of(KeyUsage.SIGN, KeyUsage.ENCRYPT, KeyUsage.VERIFY, KeyUsage.DECRYPT));
        cryptographicKeyItemRepository.save(content1);

        content.setKeyReferenceUuid(content.getUuid());
        content1.setKeyReferenceUuid(content1.getUuid());
        cryptographicKeyItemRepository.save(content);
        cryptographicKeyItemRepository.save(content1);

        Set<CryptographicKeyItem> items = new HashSet<>();
        items.add(content1);
        items.add(content);
        cryptographicKey.setItems(items);
        cryptographicKeyRepository.save(cryptographicKey);
        return cryptographicKey;
    }

    @AfterEach
    public void tearDown() {
        mockServer.stop();
    }

    @Test
    void testListCipherAttributes() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.
                        urlPathMatching(
                                "/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/cipher/attributes"
                        )
                )
                .willReturn(WireMock.ok()));

        List<BaseAttribute> attributes = cryptographicOperationService.listCipherAttributes(
                tokenInstanceReference.getSecuredParentUuid(),
                tokenProfile.getSecuredUuid(),
                key.getUuid(),
                content1.getUuid(),
                KeyAlgorithm.RSA
        );

        Assertions.assertFalse(attributes.isEmpty());

        Assertions.assertThrows(
                ValidationException.class,
                () -> cryptographicOperationService.listCipherAttributes(
                        tokenInstanceReference.getSecuredParentUuid(),
                        tokenProfile.getSecuredUuid(),
                        key.getUuid(),
                        content1.getUuid(),
                        KeyAlgorithm.ECDSA
                ));
    }

    @Test
    void testListCipherAttributes_NotFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> cryptographicOperationService.listCipherAttributes(
                        tokenInstanceReference.getSecuredParentUuid(),
                        tokenProfile.getSecuredUuid(),
                        tokenInstanceReference.getUuid(),
                        tokenProfile.getUuid(),
                        KeyAlgorithm.RSA
                )
        );
    }

    @Test
    void testListSignatureAttributes() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock
                        .urlPathMatching(
                                "/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/signature/attributes"
                        )
                )
                .willReturn(WireMock.ok()));

        List<BaseAttribute> attributes = cryptographicOperationService.listSignatureAttributes(
                tokenInstanceReference.getSecuredParentUuid(),
                tokenProfile.getSecuredUuid(),
                key.getUuid(),
                content1.getUuid(),
                KeyAlgorithm.RSA
        );

        Assertions.assertFalse(attributes.isEmpty());
    }

    @Test
    void testListSignatureAttributes_NotFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> cryptographicOperationService.listSignatureAttributes(
                        tokenInstanceReference.getSecuredParentUuid(),
                        tokenProfile.getSecuredUuid(),
                        tokenInstanceReference.getUuid(),
                        tokenProfile.getUuid(),
                        KeyAlgorithm.RSA
                )
        );
    }

    @Test
    void testListRandomDataAttributes() {
        mockServer.stubFor(WireMock
                .get(WireMock
                        .urlPathMatching(
                                "/v1/cryptographyProvider/tokens/[^/]+/keys/random/attributes"
                        )
                )
                .willReturn(WireMock.ok()));

        Assertions.assertDoesNotThrow(() -> cryptographicOperationService.listRandomAttributes(
                tokenInstanceReference.getSecuredParentUuid()
        ));
    }

    @Test
    void testListRandomDataAttributes_NotFound() {
        Assertions.assertThrows(
                ConnectorEntityNotFoundException.class,
                () -> cryptographicOperationService.listRandomAttributes(
                        tokenInstanceReference.getSecuredParentUuid()
                )
        );
    }

    @Test
    void testEncrypt() {
        CipherRequestData data = new CipherRequestData();
        data.setIdentifier("identifier");
        data.setData(Base64.getEncoder().encodeToString("Hello World!".getBytes(StandardCharsets.UTF_8)));

        CipherDataRequestDto requestDto = new CipherDataRequestDto();
        requestDto.setCipherAttributes(List.of());

        mockServer.stubFor(WireMock
                .post(WireMock
                        .urlPathMatching(
                                "/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/encrypt"
                        )
                )
                .willReturn(WireMock.okJson("{}")));

        Assertions.assertThrows(ValidationException.class, () -> cryptographicOperationService.encryptData(
                tokenInstanceReference.getSecuredParentUuid(),
                tokenProfile.getSecuredUuid(),
                key.getUuid(),
                content1.getUuid(),
                requestDto
        ));

        requestDto.setCipherData(List.of(data));

        Assertions.assertDoesNotThrow(() -> cryptographicOperationService.encryptData(
                tokenInstanceReference.getSecuredParentUuid(),
                tokenProfile.getSecuredUuid(),
                key.getUuid(),
                content1.getUuid(),
                requestDto
        ));
    }

    @Test
    void testEncrypt_CorrectTokenInstanceUuidInUrl() {
        CipherRequestData data = new CipherRequestData();
        data.setIdentifier("identifier");
        data.setData(Base64.getEncoder().encodeToString("Hello World!".getBytes(StandardCharsets.UTF_8)));

        CipherDataRequestDto requestDto = new CipherDataRequestDto();
        requestDto.setCipherData(List.of(data));
        requestDto.setCipherAttributes(List.of());

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathEqualTo(
                        "/v1/cryptographyProvider/tokens/%s/keys/%s/encrypt"
                                .formatted(tokenInstanceReference.getTokenInstanceUuid(), content1.getKeyReferenceUuid())))
                .willReturn(WireMock.okJson("{}")));

        Assertions.assertDoesNotThrow(() -> cryptographicOperationService.encryptData(
                tokenInstanceReference.getSecuredParentUuid(),
                tokenProfile.getSecuredUuid(),
                key.getUuid(),
                content1.getUuid(),
                requestDto
        ));
    }

    @Test
    void testEncrypt_NotFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> cryptographicOperationService.encryptData(
                        tokenInstanceReference.getSecuredParentUuid(),
                        tokenProfile.getSecuredUuid(),
                        key.getUuid(),
                        key.getUuid(),
                        new CipherDataRequestDto()
                )
        );
    }

    @Test
    void testEncryptValidationError() {
        Assertions.assertThrows(
                ValidationException.class,
                () -> cryptographicOperationService.encryptData(
                        tokenInstanceReference.getSecuredParentUuid(),
                        tokenProfile.getSecuredUuid(),
                        key.getUuid(),
                        content1.getUuid(),
                        new CipherDataRequestDto()
                )
        );
    }

    @Test
    void testDecrypt() {
        CipherRequestData data = new CipherRequestData();
        data.setIdentifier("identifier");
        data.setData(Base64.getEncoder().encodeToString("Hello World!".getBytes(StandardCharsets.UTF_8)));

        CipherDataRequestDto requestDto = new CipherDataRequestDto();
        requestDto.setCipherData(List.of(data));
        requestDto.setCipherAttributes(List.of());

        mockServer.stubFor(WireMock
                .post(WireMock
                        .urlPathMatching(
                                "/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/decrypt"
                        )
                )
                .willReturn(WireMock.okJson("{}")));

        Assertions.assertDoesNotThrow(() -> cryptographicOperationService.decryptData(
                tokenInstanceReference.getSecuredParentUuid(),
                tokenProfile.getSecuredUuid(),
                key.getUuid(),
                content1.getUuid(),
                requestDto
        ));
    }

    @Test
    void testDecrypt_CorrectTokenInstanceUuidInUrl() {
        CipherRequestData data = new CipherRequestData();
        data.setIdentifier("identifier");
        data.setData(Base64.getEncoder().encodeToString("Hello World!".getBytes(StandardCharsets.UTF_8)));

        CipherDataRequestDto requestDto = new CipherDataRequestDto();
        requestDto.setCipherData(List.of(data));
        requestDto.setCipherAttributes(List.of());

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathEqualTo(
                        "/v1/cryptographyProvider/tokens/%s/keys/%s/decrypt"
                                .formatted(tokenInstanceReference.getTokenInstanceUuid(), content1.getKeyReferenceUuid())))
                .willReturn(WireMock.okJson("{}")));

        Assertions.assertDoesNotThrow(() -> cryptographicOperationService.decryptData(
                tokenInstanceReference.getSecuredParentUuid(),
                tokenProfile.getSecuredUuid(),
                key.getUuid(),
                content1.getUuid(),
                requestDto
        ));
    }

    @Test
    void testDecrypt_NotFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> cryptographicOperationService.decryptData(
                        tokenInstanceReference.getSecuredParentUuid(),
                        tokenProfile.getSecuredUuid(),
                        tokenInstanceReference.getUuid(),
                        key.getUuid(),
                        new CipherDataRequestDto()
                )
        );
    }

    @Test
    void testDecryptValidationError() {
        Assertions.assertThrows(
                ValidationException.class,
                () -> cryptographicOperationService.decryptData(
                        tokenInstanceReference.getSecuredParentUuid(),
                        tokenProfile.getSecuredUuid(),
                        key.getUuid(),
                        content1.getUuid(),
                        new CipherDataRequestDto()
                )
        );
    }

    @Test
    void testEncryptData_WrongKeyUsage_DecryptOnly() {
        CryptographicKeyItem decryptOnlyItem = new CryptographicKeyItem();
        decryptOnlyItem.setLength(1024);
        decryptOnlyItem.setKey(key);
        decryptOnlyItem.setKeyUuid(key.getUuid());
        decryptOnlyItem.setType(KeyType.PUBLIC_KEY);
        decryptOnlyItem.setKeyData("some/encrypted/data");
        decryptOnlyItem.setFormat(KeyFormat.SPKI);
        decryptOnlyItem.setState(KeyState.ACTIVE);
        decryptOnlyItem.setEnabled(true);
        decryptOnlyItem.setKeyAlgorithm(KeyAlgorithm.RSA);
        decryptOnlyItem.setKeyReferenceUuid(UUID.randomUUID());
        decryptOnlyItem.setUsage(List.of(KeyUsage.DECRYPT));
        cryptographicKeyItemRepository.save(decryptOnlyItem);
        decryptOnlyItem.setKeyReferenceUuid(decryptOnlyItem.getUuid());
        cryptographicKeyItemRepository.save(decryptOnlyItem);

        CipherRequestData data = new CipherRequestData();
        data.setIdentifier("id");
        data.setData(Base64.getEncoder().encodeToString("Hello".getBytes(StandardCharsets.UTF_8)));
        CipherDataRequestDto request = new CipherDataRequestDto();
        request.setCipherData(List.of(data));
        request.setCipherAttributes(List.of());

        var tokenParentUuid = tokenInstanceReference.getSecuredParentUuid();
        var tokenProfileUuid = tokenProfile.getSecuredUuid();
        var keyUuid = key.getUuid();
        var decryptOnlyItemUuid = decryptOnlyItem.getUuid();
        Assertions.assertThrows(ValidationException.class, () -> cryptographicOperationService.encryptData(
                tokenParentUuid, tokenProfileUuid, keyUuid, decryptOnlyItemUuid, request));
    }

    @Test
    void testDecryptData_WrongKeyUsage_EncryptOnly() {
        CryptographicKeyItem encryptOnlyItem = new CryptographicKeyItem();
        encryptOnlyItem.setLength(1024);
        encryptOnlyItem.setKey(key);
        encryptOnlyItem.setKeyUuid(key.getUuid());
        encryptOnlyItem.setType(KeyType.PUBLIC_KEY);
        encryptOnlyItem.setKeyData("some/encrypted/data");
        encryptOnlyItem.setFormat(KeyFormat.SPKI);
        encryptOnlyItem.setState(KeyState.ACTIVE);
        encryptOnlyItem.setEnabled(true);
        encryptOnlyItem.setKeyAlgorithm(KeyAlgorithm.RSA);
        encryptOnlyItem.setKeyReferenceUuid(UUID.randomUUID());
        encryptOnlyItem.setUsage(List.of(KeyUsage.ENCRYPT));
        cryptographicKeyItemRepository.save(encryptOnlyItem);
        encryptOnlyItem.setKeyReferenceUuid(encryptOnlyItem.getUuid());
        cryptographicKeyItemRepository.save(encryptOnlyItem);

        CipherRequestData data = new CipherRequestData();
        data.setIdentifier("id");
        data.setData(Base64.getEncoder().encodeToString("Hello".getBytes(StandardCharsets.UTF_8)));
        CipherDataRequestDto request = new CipherDataRequestDto();
        request.setCipherData(List.of(data));
        request.setCipherAttributes(List.of());

        var tokenParentUuid = tokenInstanceReference.getSecuredParentUuid();
        var tokenProfileUuid = tokenProfile.getSecuredUuid();
        var keyUuid = key.getUuid();
        var encryptOnlyItemUuid = encryptOnlyItem.getUuid();
        Assertions.assertThrows(ValidationException.class, () -> cryptographicOperationService.decryptData(
                tokenParentUuid, tokenProfileUuid, keyUuid, encryptOnlyItemUuid, request));
    }

    @Test
    void testSignData_WrongKeyUsage_VerifyOnly() {
        CryptographicKeyItem verifyOnlyItem = new CryptographicKeyItem();
        verifyOnlyItem.setLength(1024);
        verifyOnlyItem.setKey(key);
        verifyOnlyItem.setKeyUuid(key.getUuid());
        verifyOnlyItem.setType(KeyType.PRIVATE_KEY);
        verifyOnlyItem.setKeyData("some/encrypted/data");
        verifyOnlyItem.setFormat(KeyFormat.PRKI);
        verifyOnlyItem.setState(KeyState.ACTIVE);
        verifyOnlyItem.setEnabled(true);
        verifyOnlyItem.setKeyAlgorithm(KeyAlgorithm.RSA);
        verifyOnlyItem.setKeyReferenceUuid(UUID.randomUUID());
        verifyOnlyItem.setUsage(List.of(KeyUsage.VERIFY));
        cryptographicKeyItemRepository.save(verifyOnlyItem);
        verifyOnlyItem.setKeyReferenceUuid(verifyOnlyItem.getUuid());
        cryptographicKeyItemRepository.save(verifyOnlyItem);

        SignatureRequestData data = new SignatureRequestData();
        data.setIdentifier("id");
        data.setData(Base64.getEncoder().encodeToString("Hello".getBytes(StandardCharsets.UTF_8)));
        SignDataRequestDto request = new SignDataRequestDto();
        request.setData(List.of(data));

        var tokenParentUuid = tokenInstanceReference.getSecuredParentUuid();
        var tokenProfileUuid = tokenProfile.getSecuredUuid();
        var keyUuid = key.getUuid();
        var verifyOnlyItemUuid = verifyOnlyItem.getUuid();
        Assertions.assertThrows(ValidationException.class, () -> cryptographicOperationService.signData(
                tokenParentUuid, tokenProfileUuid, keyUuid, verifyOnlyItemUuid, request));
    }

    @Test
    void testVerifyData_WrongKeyUsage_SignOnly() {
        CryptographicKeyItem signOnlyItem = new CryptographicKeyItem();
        signOnlyItem.setLength(1024);
        signOnlyItem.setKey(key);
        signOnlyItem.setKeyUuid(key.getUuid());
        signOnlyItem.setType(KeyType.PUBLIC_KEY);
        signOnlyItem.setKeyData("some/encrypted/data");
        signOnlyItem.setFormat(KeyFormat.SPKI);
        signOnlyItem.setState(KeyState.ACTIVE);
        signOnlyItem.setEnabled(true);
        signOnlyItem.setKeyAlgorithm(KeyAlgorithm.RSA);
        signOnlyItem.setKeyReferenceUuid(UUID.randomUUID());
        signOnlyItem.setUsage(List.of(KeyUsage.SIGN));
        cryptographicKeyItemRepository.save(signOnlyItem);
        signOnlyItem.setKeyReferenceUuid(signOnlyItem.getUuid());
        cryptographicKeyItemRepository.save(signOnlyItem);

        SignatureRequestData signature = new SignatureRequestData();
        signature.setIdentifier("id");
        signature.setData(Base64.getEncoder().encodeToString("Hello".getBytes(StandardCharsets.UTF_8)));
        VerifyDataRequestDto request = new VerifyDataRequestDto();
        request.setSignatures(List.of(signature));

        var tokenParentUuid = tokenInstanceReference.getSecuredParentUuid();
        var tokenProfileUuid = tokenProfile.getSecuredUuid();
        var keyUuid = key.getUuid();
        var signOnlyItemUuid = signOnlyItem.getUuid();
        Assertions.assertThrows(ValidationException.class, () -> cryptographicOperationService.verifyData(
                tokenParentUuid, tokenProfileUuid, keyUuid, signOnlyItemUuid, request));
    }

    @Test
    void testSign_RSA() {
        SignatureRequestData data = new SignatureRequestData();
        data.setIdentifier("identifier");
        data.setData(Base64.getEncoder().encodeToString("Hello World!".getBytes(StandardCharsets.UTF_8)));

        SignDataRequestDto requestDto = new SignDataRequestDto();
        requestDto.setData(List.of(data));
        requestDto.setSignatureAttributes(List.of());

        RequestAttributeV3 reqDto1 = new RequestAttributeV3();
        reqDto1.setName("data_rsaSigScheme");
        reqDto1.setContent(List.of(new StringAttributeContentV3("PSS")));

        RequestAttributeV3 reqDto2 = new RequestAttributeV3();
        reqDto2.setName("data_sigDigest");
        reqDto2.setContent(List.of(new StringAttributeContentV3("SHA-256")));

        requestDto.setSignatureAttributes(List.of(reqDto1, reqDto2));

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/sign"))
                .willReturn(WireMock.okJson("{}")));

        Assertions.assertDoesNotThrow(() -> cryptographicOperationService.signData(
                tokenInstanceReference.getSecuredParentUuid(),
                tokenProfile.getSecuredUuid(),
                key.getUuid(),
                content1.getUuid(),
                requestDto
        ));
    }

    @Test
    void testSign_CorrectTokenInstanceUuidInUrl() {
        SignatureRequestData data = new SignatureRequestData();
        data.setIdentifier("identifier");
        data.setData(Base64.getEncoder().encodeToString("Hello World!".getBytes(StandardCharsets.UTF_8)));

        RequestAttributeV3 reqDto1 = new RequestAttributeV3();
        reqDto1.setName("data_rsaSigScheme");
        reqDto1.setContent(List.of(new StringAttributeContentV3("PSS")));

        RequestAttributeV3 reqDto2 = new RequestAttributeV3();
        reqDto2.setName("data_sigDigest");
        reqDto2.setContent(List.of(new StringAttributeContentV3("SHA-256")));

        SignDataRequestDto requestDto = new SignDataRequestDto();
        requestDto.setData(List.of(data));
        requestDto.setSignatureAttributes(List.of(reqDto1, reqDto2));

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathEqualTo(
                        "/v1/cryptographyProvider/tokens/%s/keys/%s/sign"
                                .formatted(tokenInstanceReference.getTokenInstanceUuid(), content1.getKeyReferenceUuid())))
                .willReturn(WireMock.okJson("{}")));

        Assertions.assertDoesNotThrow(() -> cryptographicOperationService.signData(
                tokenInstanceReference.getSecuredParentUuid(),
                tokenProfile.getSecuredUuid(),
                key.getUuid(),
                content1.getUuid(),
                requestDto
        ));
    }

    @Test
    void testSign_NotFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> cryptographicOperationService.signData(
                        tokenInstanceReference.getSecuredParentUuid(),
                        tokenProfile.getSecuredUuid(),
                        tokenInstanceReference.getUuid(),
                        key.getUuid(),
                        new SignDataRequestDto()
                )
        );
    }

    @Test
    void testSignValidationError() {
        Assertions.assertThrows(
                ValidationException.class,
                () -> cryptographicOperationService.signData(
                        tokenInstanceReference.getSecuredParentUuid(),
                        tokenProfile.getSecuredUuid(),
                        key.getUuid(),
                        content1.getUuid(),
                        new SignDataRequestDto()
                )
        );
    }

    @Test
    void testVerify() throws ConnectorException, NotFoundException {
        SignatureRequestData data = new SignatureRequestData();
        data.setIdentifier("identifier");
        data.setData(Base64.getEncoder().encodeToString("Hello World!".getBytes(StandardCharsets.UTF_8)));

        VerifyDataRequestDto requestDto = new VerifyDataRequestDto();
        requestDto.setData(List.of(data));
        requestDto.setSignatureAttributes(List.of());
        requestDto.setSignatures(List.of(data));

        RequestAttributeV3 reqDto1 = new RequestAttributeV3();
        reqDto1.setName("data_rsaSigScheme");
        reqDto1.setContent(List.of(new StringAttributeContentV3("PSS")));

        RequestAttributeV3 reqDto2 = new RequestAttributeV3();
        reqDto2.setName("data_sigDigest");
        reqDto2.setContent(List.of(new StringAttributeContentV3("SHA-256")));

        requestDto.setSignatureAttributes(List.of(reqDto1, reqDto2));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/verify"))
                .willReturn(WireMock.okJson("{}")));

        cryptographicOperationService.verifyData(
                tokenInstanceReference.getSecuredParentUuid(),
                tokenProfile.getSecuredUuid(),
                key.getUuid(),
                content1.getUuid(),
                requestDto
        );
    }

    @Test
    void testVerify_CorrectTokenInstanceUuidInUrl() throws ConnectorException, NotFoundException {
        SignatureRequestData data = new SignatureRequestData();
        data.setIdentifier("identifier");
        data.setData(Base64.getEncoder().encodeToString("Hello World!".getBytes(StandardCharsets.UTF_8)));

        RequestAttributeV3 reqDto1 = new RequestAttributeV3();
        reqDto1.setName("data_rsaSigScheme");
        reqDto1.setContent(List.of(new StringAttributeContentV3("PSS")));

        RequestAttributeV3 reqDto2 = new RequestAttributeV3();
        reqDto2.setName("data_sigDigest");
        reqDto2.setContent(List.of(new StringAttributeContentV3("SHA-256")));

        VerifyDataRequestDto requestDto = new VerifyDataRequestDto();
        requestDto.setData(List.of(data));
        requestDto.setSignatures(List.of(data));
        requestDto.setSignatureAttributes(List.of(reqDto1, reqDto2));

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathEqualTo(
                        "/v1/cryptographyProvider/tokens/%s/keys/%s/verify"
                                .formatted(tokenInstanceReference.getTokenInstanceUuid(), content1.getKeyReferenceUuid())))
                .willReturn(WireMock.okJson("{}")));

        Assertions.assertDoesNotThrow(() -> cryptographicOperationService.verifyData(
                tokenInstanceReference.getSecuredParentUuid(),
                tokenProfile.getSecuredUuid(),
                key.getUuid(),
                content1.getUuid(),
                requestDto
        ));
    }

    @Test
    void testVerify_NotFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> cryptographicOperationService.verifyData(
                        tokenInstanceReference.getSecuredParentUuid(),
                        tokenProfile.getSecuredUuid(),
                        key.getUuid(),
                        key.getUuid(),
                        new VerifyDataRequestDto()
                )
        );
    }

    @Test
    void testVerifyValidationError() {
        Assertions.assertThrows(
                ValidationException.class,
                () -> cryptographicOperationService.verifyData(
                        tokenInstanceReference.getSecuredParentUuid(),
                        tokenProfile.getSecuredUuid(),
                        key.getUuid(),
                        content1.getUuid(),
                        new VerifyDataRequestDto()
                )
        );
    }

    @Test
    void testRandomData() {
        String response = """
                {
                    "data": "cmFuZG9tRGF0YQ=="
                }
                """;

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/random"))
                .willReturn(WireMock.okJson(response)));

        RandomDataRequestDto requestDto = new RandomDataRequestDto();
        requestDto.setLength(32);
        requestDto.setAttributes(List.of());

        Assertions.assertDoesNotThrow(() -> cryptographicOperationService.randomData(tokenInstanceReference.getSecuredParentUuid(), requestDto));
    }

    @Test
    void testGenerateCsrWithAltExtensions() throws NotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, AttributeException, InvalidAlgorithmParameterException, SignatureException, InvalidKeyException, CertificateRequestException {
        KeyPair altKeyPair = generateKeyPair("SLH-DSA", SLHDSAParameterSpec.slh_dsa_sha2_128f, 0);
        KeyPair defaultKeyPair = generateKeyPair("RSA", null, 1024);
        CryptographicKey altKey = createAndSaveKey("altKey", KeyAlgorithm.SLHDSA, Base64.getEncoder().encodeToString(altKeyPair.getPublic().getEncoded()));
        CryptographicKey defaultKey = createAndSaveKey("defKey", KeyAlgorithm.RSA, Base64.getEncoder().encodeToString(defaultKeyPair.getPublic().getEncoded()));

        List<RequestAttribute> rsaSignatureAttributes = new ArrayList<>();
        rsaSignatureAttributes.add(RsaSignatureAttributes.buildRequestRsaSigScheme(RsaSignatureScheme.PKCS1_v1_5));
        rsaSignatureAttributes.add(RsaSignatureAttributes.buildRequestDigest(DigestAlgorithm.SHA3_256));

        String altPrivateKeyReferenceUuid = altKey.getKeyItems().stream().filter(c -> c.getType() == KeyType.PRIVATE_KEY).findFirst().get().getKeyReferenceUuid();
        String defaultPrivateKeyReferenceUuid = defaultKey.getKeyItems().stream().filter(c -> c.getType() == KeyType.PRIVATE_KEY).findFirst().get().getKeyReferenceUuid();

        mockSignResponse(altPrivateKeyReferenceUuid, generateSignature(altKeyPair, altKeyPair.getPublic().getAlgorithm()));
        mockSignResponse(defaultPrivateKeyReferenceUuid, generateSignature(defaultKeyPair, "SHA256withRSA"));

        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/verify"))
                .willReturn(WireMock.okJson("""
                        {
                            "verifications" : [
                                {
                                    "result": true
                                }
                            ]
                        }
                        """)));

        String csr = cryptographicOperationService.generateCsr(defaultKey.getUuid(), tokenProfile.getUuid(), new X500Principal("CN=alt"),
                rsaSignatureAttributes, altKey.getUuid(), tokenProfile.getUuid(), new ArrayList<>());
        CertificateRequest certificateRequest = CertificateRequestUtils.createCertificateRequest(csr, CertificateRequestFormat.PKCS10);
        Assertions.assertNotNull(certificateRequest.getAltSignatureAlgorithm());
        Assertions.assertNotNull(certificateRequest.getAltPublicKey());
        Assertions.assertInstanceOf(SLHDSAPublicKey.class, certificateRequest.getAltPublicKey());
        JcaPKCS10CertificationRequest pkcs10CertificationRequest = new JcaPKCS10CertificationRequest(Base64.getDecoder().decode(csr));
        Assertions.assertNotNull(Arrays.stream(pkcs10CertificationRequest.getAttributes()).filter(attribute -> attribute.getAttrType().equals(Extension.altSignatureValue)));
    }

    private void mockSignResponse(String keyUuid, String signature) {
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathEqualTo("/v1/cryptographyProvider/tokens/%s/keys/%s/sign".formatted(tokenInstanceReference.getTokenInstanceUuid(), keyUuid)))
                .willReturn(WireMock.okJson("""
                        {
                            "signatures" : [
                                {
                                    "data": "%s"
                                }
                            ]
                        }
                        """.formatted(signature))));
    }

    private static KeyPair generateKeyPair(String algorithm, AlgorithmParameterSpec parameterSpec, int keySize) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        if (parameterSpec != null) {
            keyPairGenerator.initialize(parameterSpec);
        } else {
            keyPairGenerator.initialize(keySize);
        }
        return keyPairGenerator.generateKeyPair();
    }

    private String generateSignature(KeyPair keyPair, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(keyPair.getPrivate());
        signature.update(keyPair.getPublic().getEncoded());
        byte[] signedData = signature.sign();
        return Base64.getEncoder().encodeToString(signedData);
    }

}

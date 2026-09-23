package com.otilm.core.integration.service;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotSupportedException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.CipherRequestData;
import com.otilm.api.model.client.cryptography.operations.DecryptDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.EncryptDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.RandomDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.RandomDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignatureRequestData;
import com.otilm.api.model.client.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.VerifyDataResponseDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyEventHistory;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CryptographicKeyEventHistoryRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.service.CryptographicOperationExternalService;
import com.otilm.core.service.CryptographicOperationInternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.builders.DataAttributeV3Builder;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class CryptographicOperationServiceV2ITest extends BaseSpringBootTest {

    private static final String DATA = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3});
    private static final String SIGNATURE = Base64.getEncoder().encodeToString(new byte[]{9, 9});

    @Autowired
    private CryptographicOperationExternalService operationService;
    @Autowired
    private CryptographicOperationInternalService internalOperationService;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    @Autowired
    private CryptographicKeyEventHistoryRepository eventHistoryRepository;
    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private ConnectorMockFactory connectorMockFactory;

    private CryptographyProviderV2ConnectorMock connectorMock;
    private Connector connector;
    private ConnectorInterfaceEntity cryptographyInterface;
    private TokenInstanceReference token;
    private TokenProfile profile;
    private CryptographicKey key;
    private CryptographicKeyItem privateKey;

    @BeforeEach
    void setUp() throws Exception {
        connectorMock = connectorMockFactory.startCryptographyProviderV2();
        connector = persistV2Connector(connectorMock.getUrl());
        cryptographyInterface = persistCryptographyInterface(connector);
        token = persistToken(cryptographyInterface, "v2-operations-token");
        profile = persistProfile(List.of(KeyUsage.SIGN, KeyUsage.VERIFY, KeyUsage.ENCRYPT, KeyUsage.DECRYPT));
        key = persistKey();
        privateKey = persistKeyItem(KeyType.PRIVATE_KEY, "hsm-key-17");
        persistAttribute(Resource.TOKEN, token.getUuid(), "token-slot", "slot-7");
        persistAttribute(Resource.TOKEN_PROFILE, profile.getUuid(), "profile-policy", "signing");
    }

    @AfterEach
    void tearDown() {
        connectorMock.stop();
    }

    @Test
    void signData_sendsScopedSynchronousRequest_andRecordsSuccess() throws Exception {
        // given
        connectorMock
                .stubOperationAttributes("sign", signSchema())
                .stubOperation("sign", "{\"signatures\":[{\"identifier\":\"0\",\"data\":\"" + SIGNATURE + "\"}]}");
        String expectedRequest = "{\"tokenAttributes\":[{\"name\":\"token-slot\",\"content\":[{\"data\":\"slot-7\"}]}],"
                + "\"tokenProfileAttributes\":[{\"name\":\"profile-policy\",\"content\":[{\"data\":\"signing\"}]}],"
                + "\"keyMeta\":[{\"name\":\"provider-handle\"}]," + "\"executionMode\":\"synchronous\","
                + "\"signatureAttributes\":[{\"name\":\"signatureAlgorithm\",\"content\":[{\"data\":\"SHA256withRSA\"}]}],"
                + "\"data\":[{\"identifier\":\"0\",\"data\":\"" + DATA + "\"}]}";

        // when
        SignDataResponseDto response = operationService
                .signData(token.getSecuredParentUuid(), profile.getSecuredUuid(), key.getUuid(), privateKey.getUuid(),
                        signRequest());

        // then
        assertEquals(SIGNATURE, response.getSignatures().get(0).getData());
        assertNull(response.getSignatures().get(0).getIdentifier());
        connectorMock.verifyOperationRequestContaining("sign", expectedRequest);
        assertEquals(KeyEventStatus.SUCCESS, onlyEvent(KeyEvent.SIGN).getStatus());
    }

    @Test
    void signData_failsClearly_whenConnectorAnswersAsynchronously() throws Exception {
        // given
        connectorMock
                .stubOperationAttributes("sign", signSchema())
                .stubOperationAccepted("sign", "{\"operationMeta\":[{\"name\":\"tracking\"}]}");

        // when
        Executable sign = () -> operationService
                .signData(token.getSecuredParentUuid(), profile.getSecuredUuid(), key.getUuid(), privateKey.getUuid(),
                        signRequest());

        // then
        assertThrows(ConnectorException.class, sign);
        assertEquals(KeyEventStatus.FAILED, onlyEvent(KeyEvent.SIGN).getStatus());
    }

    @Test
    void signData_propagatesConnectorError_andRecordsFailure() throws Exception {
        // given
        connectorMock.stubOperationAttributes("sign", signSchema()).stubOperationError("sign");

        // when
        Executable sign = () -> operationService
                .signData(token.getSecuredParentUuid(), profile.getSecuredUuid(), key.getUuid(), privateKey.getUuid(),
                        signRequest());

        // then
        assertThrows(ConnectorException.class, sign);
        assertEquals(KeyEventStatus.FAILED, onlyEvent(KeyEvent.SIGN).getStatus());
    }

    @Test
    void signData_rejectsUnknownAttribute_withoutCallingSign() throws Exception {
        // given
        connectorMock
                .stubOperationAttributes("sign", signSchema(dataAttributeJson("digest", true)))
                .stubOperation("sign", "{}");
        SignDataRequestDto request = signRequest();
        RequestAttributeV3 wrong = new RequestAttributeV3(UUID.randomUUID(), "not-digest", AttributeContentType.STRING,
                List.of(new StringAttributeContentV3("x")));
        request.setSignatureAttributes(List.of(wrong));

        // when
        Executable sign = () -> operationService
                .signData(token.getSecuredParentUuid(), profile.getSecuredUuid(), key.getUuid(), privateKey.getUuid(),
                        request);

        // then
        assertThrows(ValidationException.class, sign);
        connectorMock.verifyNoOperationRequest("sign");
    }

    @Test
    void signData_rejectsMismatchedTokenProfilePath() throws Exception {
        // given
        TokenProfile otherProfile = persistProfile(List.of(KeyUsage.SIGN));

        // when
        Executable sign = () -> operationService
                .signData(token.getSecuredParentUuid(), otherProfile.getSecuredUuid(), key.getUuid(),
                        privateKey.getUuid(), signRequest());

        // then
        assertThrows(ValidationException.class, sign);
        connectorMock.verifyNoOperationRequest("sign");
    }

    @Test
    void signData_rejectsMismatchedTokenPath() throws Exception {
        // given
        TokenInstanceReference otherToken = persistToken(cryptographyInterface, "other-v2-operations-token");

        // when
        Executable sign = () -> operationService
                .signData(otherToken.getSecuredParentUuid(), profile.getSecuredUuid(), key.getUuid(),
                        privateKey.getUuid(), signRequest());

        // then
        assertThrows(ValidationException.class, sign);
        connectorMock.verifyNoOperationRequest("sign");
    }

    @Test
    void verifyData_pairsByPosition_andReturnsResult() throws Exception {
        // given
        connectorMock
                .stubOperationAttributes("verify", "[]")
                .stubOperation("verify", "{\"verifications\":[{\"identifier\":\"0\",\"result\":true}]}");
        VerifyDataRequestDto request = new VerifyDataRequestDto();
        request.setSignatureAttributes(List.of());
        request.setData(List.of(signatureData(DATA)));
        request.setSignatures(List.of(signatureData(SIGNATURE)));

        // when
        VerifyDataResponseDto response = operationService
                .verifyData(token.getSecuredParentUuid(), profile.getSecuredUuid(), key.getUuid(), privateKey.getUuid(),
                        request);

        // then
        assertTrue(response.getVerifications().get(0).isResult());
        connectorMock
                .verifyOperationRequestContaining("verify",
                        "{\"data\":[{\"identifier\":\"0\"}],\"signatures\":[{\"identifier\":\"0\"}]}");
    }

    @Test
    void encryptData_returnsConnectorPayload_andRecordsSuccess() throws Exception {
        // given
        connectorMock
                .stubOperationAttributes("encrypt", "[]")
                .stubOperation("encrypt",
                        "{\"encryptedData\":[{\"identifier\":\"0\",\"data\":\"" + SIGNATURE + "\"}]}");

        // when
        EncryptDataResponseDto encrypted = operationService
                .encryptData(token.getSecuredParentUuid(), profile.getSecuredUuid(), key.getUuid(),
                        privateKey.getUuid(), cipherRequest());

        // then
        assertEquals(SIGNATURE, encrypted.getEncryptedData().get(0).getData());
        assertEquals(KeyEventStatus.SUCCESS, onlyEvent(KeyEvent.ENCRYPT).getStatus());
    }

    @Test
    void decryptData_returnsConnectorPayload_andRecordsSuccess() throws Exception {
        // given
        connectorMock
                .stubOperationAttributes("decrypt", "[]")
                .stubOperation("decrypt", "{\"decryptedData\":[{\"identifier\":\"0\",\"data\":\"" + DATA + "\"}]}");

        // when
        DecryptDataResponseDto decrypted = operationService
                .decryptData(token.getSecuredParentUuid(), profile.getSecuredUuid(), key.getUuid(),
                        privateKey.getUuid(), cipherRequest());

        // then
        assertEquals(DATA, decrypted.getDecryptedData().get(0).getData());
        assertEquals(KeyEventStatus.SUCCESS, onlyEvent(KeyEvent.DECRYPT).getStatus());
    }

    private static CipherDataRequestDto cipherRequest() {
        CipherDataRequestDto request = new CipherDataRequestDto();
        request.setCipherAttributes(List.of());
        CipherRequestData item = new CipherRequestData();
        item.setData(DATA);
        request.setCipherData(List.of(item));
        return request;
    }

    @Test
    void listSignAttributes_returnsConnectorSchema_andSendsKeyMeta() throws Exception {
        // given
        UUID attributeUuid = UUID.randomUUID();
        connectorMock.stubOperationAttributes("sign", signSchema(dataAttributeJson(attributeUuid, "digest", false)));

        // when
        List<BaseAttribute> schema = operationService
                .listSignAttributes(token.getSecuredParentUuid(), profile.getSecuredUuid(), key.getUuid(),
                        privateKey.getUuid());

        // then
        assertEquals(List.of(SignatureAlgorithmAttribute.NAME, "digest"),
                schema.stream().map(BaseAttribute::getName).toList());
        connectorMock
                .verifyOperationRequestContaining("sign/attributes", "{\"keyMeta\":[{\"name\":\"provider-handle\"}]}");
    }

    @Test
    void listSignatureAttributes_deprecated_rejectsV2Key() {
        // when
        Executable list = () -> operationService
                .listSignatureAttributes(token.getSecuredParentUuid(), profile.getSecuredUuid(), key.getUuid(),
                        privateKey.getUuid(), KeyAlgorithm.RSA);

        // then
        assertThrows(NotSupportedException.class, list);
    }

    @Test
    void generateCsr_rejectsV2Key() {
        // given
        persistKeyItem(KeyType.PUBLIC_KEY, "hsm-key-17-pub");

        // when
        Executable generateCsr = () -> internalOperationService
                .generateCsr(key.getUuid(), profile.getUuid(), new X500Principal("CN=test"), null, List.of(), null,
                        null, null);

        // then
        NotSupportedException exception = assertThrows(NotSupportedException.class, generateCsr);
        assertTrue(exception.getMessage().contains("cryptography provider v2"));
    }

    @Test
    void randomData_sendsTokenProfileScope_andReturnsBase64() throws Exception {
        // given
        String randomBytes = Base64.getEncoder().encodeToString(new byte[]{4, 4, 4, 4});
        connectorMock
                .stubOperationAttributes("random", "[]")
                .stubOperation("random", "{\"data\":\"" + randomBytes + "\"}");
        RandomDataRequestDto request = new RandomDataRequestDto();
        request.setLength(4);
        request.setAttributes(List.of());

        // when
        RandomDataResponseDto response = operationService
                .randomData(token.getSecuredParentUuid(), profile.getSecuredUuid(), request);

        // then
        assertEquals(randomBytes, response.getData());
        connectorMock
                .verifyOperationRequestContaining("random",
                        "{\"tokenAttributes\":[{\"name\":\"token-slot\"}],"
                                + "\"tokenProfileAttributes\":[{\"name\":\"profile-policy\"}],"
                                + "\"keyUsages\":[\"sign\",\"verify\",\"encrypt\",\"decrypt\"],"
                                + "\"length\":4,\"operationAttributes\":[]}");
    }

    @Test
    void randomData_rejectsTokenOnlyForm_forV2Token() {
        // given
        RandomDataRequestDto request = new RandomDataRequestDto();
        request.setLength(4);
        request.setAttributes(List.of());

        // when
        Executable generate = () -> operationService.randomData(token.getSecuredUuid(), request);

        // then
        NotSupportedException failure = assertThrows(NotSupportedException.class, generate);
        assertEquals("Random-data generation on a cryptography provider v2 token requires a token profile; use the "
                + "token-profile form of this endpoint.", failure.getMessage());
        connectorMock.verifyNoOperationRequest("random");
    }

    @Test
    void signDataWithoutEventHistory_reachesV2Connector_withoutHistory() throws Exception {
        // given
        connectorMock
                .stubOperationAttributes("sign", signSchema())
                .stubOperation("sign", "{\"signatures\":[{\"identifier\":\"0\",\"data\":\"" + SIGNATURE + "\"}]}");

        // when
        SignDataResponseDto response = internalOperationService
                .signDataWithoutEventHistory(token.getSecuredParentUuid(), profile.getSecuredUuid(), key.getUuid(),
                        privateKey.getUuid(), signRequest());

        // then
        assertEquals(SIGNATURE, response.getSignatures().get(0).getData());
        assertTrue(eventHistoryRepository.findAll().isEmpty());
    }

    // ---- fixtures ----

    private Connector persistV2Connector(String url) {
        Connector value = new Connector();
        value.setName("operations-provider-v2");
        value.setUrl(url);
        value.setVersion(ConnectorVersion.V2);
        value.setStatus(ConnectorStatus.CONNECTED);
        return connectorRepository.save(value);
    }

    private ConnectorInterfaceEntity persistCryptographyInterface(Connector owner) {
        ConnectorInterfaceEntity value = new ConnectorInterfaceEntity();
        value.setConnector(owner);
        value.setConnectorUuid(owner.getUuid());
        value.setInterfaceCode(ConnectorInterface.CRYPTOGRAPHY);
        value.setVersion("v2");
        value.setFeatures(List.of(FeatureFlag.STATELESS));
        value = connectorInterfaceRepository.save(value);
        owner.getInterfaces().add(value);
        return value;
    }

    private TokenInstanceReference persistToken(ConnectorInterfaceEntity iface, String name) {
        TokenInstanceReference value = new TokenInstanceReference();
        value.setName(name);
        value.setConnector(connector);
        value.setConnectorUuid(connector.getUuid());
        value.setConnectorInterface(iface);
        value.setKind("SOFT");
        value.setStatus(TokenInstanceStatus.ACTIVATED);
        return tokenInstanceReferenceRepository.save(value);
    }

    private TokenProfile persistProfile(List<KeyUsage> usages) {
        TokenProfile value = new TokenProfile();
        value.setName("profile-" + UUID.randomUUID());
        value.setTokenInstanceReference(token);
        value.setTokenInstanceName(token.getName());
        value.setEnabled(true);
        value.setUsage(usages);
        return tokenProfileRepository.save(value);
    }

    private CryptographicKey persistKey() {
        CryptographicKey value = new CryptographicKey();
        value.setName("v2-key");
        value.setTokenProfile(profile);
        value.setTokenInstanceReference(token);
        return cryptographicKeyRepository.save(value);
    }

    private CryptographicKeyItem persistKeyItem(KeyType type, String opaqueHandle) {
        MetadataAttributeV3 handle = new MetadataAttributeV3();
        handle.setUuid(UUID.randomUUID().toString());
        handle.setName("provider-handle");
        handle.setType(AttributeType.META);
        handle.setContentType(AttributeContentType.STRING);
        handle.setProperties(new MetadataAttributeProperties());
        handle.setContent(List.of(new StringAttributeContentV3(opaqueHandle)));
        CryptographicKeyItem value = new CryptographicKeyItem();
        value.setKey(key);
        value.setKeyUuid(key.getUuid());
        value.setType(type);
        value.setKeyAlgorithm(KeyAlgorithm.RSA);
        value.setFormat(KeyFormat.PRKI);
        value.setLength(2048);
        value.setState(KeyState.ACTIVE);
        value.setEnabled(true);
        value.setUsage(List.of(KeyUsage.SIGN, KeyUsage.VERIFY, KeyUsage.ENCRYPT, KeyUsage.DECRYPT));
        value.setKeyMeta(List.of(handle));
        return cryptographicKeyItemRepository.save(value);
    }

    private void persistAttribute(Resource resource, UUID objectUuid, String name, String content) throws Exception {
        UUID attributeUuid = UUID.randomUUID();
        attributeEngine
                .updateDataAttributeDefinitions(connector.getUuid(), null, List
                        .of(DataAttributeV3Builder.aDataAttribute().withUuid(attributeUuid).withName(name).build()));
        RequestAttributeV3 request = new RequestAttributeV3(attributeUuid, name, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3(content)));
        attributeEngine
                .updateObjectDataAttributesContent(
                        ObjectAttributeContentInfo.builder(resource, objectUuid).connector(connector.getUuid()).build(),
                        List.of(request));
    }

    private static SignDataRequestDto signRequest() {
        SignDataRequestDto request = new SignDataRequestDto();
        request
                .setSignatureAttributes(
                        List.of(SignatureAlgorithmAttribute.request(SignatureAlgorithm.SHA256_WITH_RSA)));
        request.setData(List.of(signatureData(DATA)));
        return request;
    }

    private static SignatureRequestData signatureData(String base64) {
        SignatureRequestData item = new SignatureRequestData();
        item.setData(base64);
        return item;
    }

    private CryptographicKeyEventHistory onlyEvent(KeyEvent event) {
        List<CryptographicKeyEventHistory> events = eventHistoryRepository
                .findAll()
                .stream()
                .filter(history -> history.getEvent() == event)
                .toList();
        assertEquals(1, events.size());
        return events.get(0);
    }

    private static String signSchema(String... otherDefinitions) {
        String signatureAlgorithm = "{\"uuid\":\"" + SignatureAlgorithmAttribute.ATTRIBUTE_UUID + "\",\"name\":\""
                + SignatureAlgorithmAttribute.NAME + "\",\"type\":\"data\",\"contentType\":\"string\",\"version\":2,"
                + "\"properties\":{\"label\":\"Signature Algorithm\",\"visible\":true,\"required\":true,"
                + "\"readOnly\":false,\"list\":true,\"multiSelect\":false},\"content\":[{\"data\":\"SHA256withRSA\"}]}";
        return Stream
                .concat(Stream.of(signatureAlgorithm), Stream.of(otherDefinitions))
                .collect(Collectors.joining(",", "[", "]"));
    }

    private static String dataAttributeJson(String name, boolean required) {
        return dataAttributeJson(UUID.randomUUID(), name, required);
    }

    private static String dataAttributeJson(UUID uuid, String name, boolean required) {
        return "{\"uuid\":\"" + uuid + "\",\"name\":\"" + name + "\",\"type\":\"data\",\"contentType\":\"string\","
                + "\"version\":3,\"properties\":{\"label\":\"" + name + "\",\"visible\":true,\"required\":" + required
                + ",\"readOnly\":false,\"list\":false,\"multiSelect\":false}}";
    }
}

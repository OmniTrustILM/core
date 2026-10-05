package com.otilm.core.integration.service;

import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.cryptography.operations.RandomDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.RandomDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignatureRequestData;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.service.CryptographicOperationExternalService;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.handler.token.TokenProviderAdapter;
import com.otilm.core.service.handler.token.TokenProviderAdapterFactory;
import com.otilm.core.service.impl.CryptographicOperationServiceImpl;
import com.otilm.core.util.BaseSpringBootTest;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SpringBootTest
class CryptographicOperationServiceTransactionITest extends BaseSpringBootTest {

    @MockitoBean
    private KeyProviderAdapterFactory keyProviderAdapterFactory;
    @MockitoBean
    private TokenProviderAdapterFactory tokenProviderAdapterFactory;
    @Autowired
    private CryptographicOperationExternalService operationService;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;

    private TokenInstanceReference token;
    private TokenProfile profile;
    private CryptographicKey key;
    private CryptographicKeyItem privateKey;

    @BeforeEach
    void setUp() {
        Connector connector = new Connector();
        connector.setName("legacy-provider");
        connector.setUrl("http://localhost:1");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);
        token = new TokenInstanceReference();
        token.setName("legacy-token");
        token.setConnector(connector);
        token.setConnectorUuid(connector.getUuid());
        token.setKind("SOFT");
        token.setStatus(TokenInstanceStatus.ACTIVATED);
        token.setTokenInstanceUuid(UUID.randomUUID().toString());
        token = tokenInstanceReferenceRepository.save(token);
        profile = new TokenProfile();
        profile.setName("legacy-profile");
        profile.setTokenInstanceReference(token);
        profile.setTokenInstanceName(token.getName());
        profile.setEnabled(true);
        profile.setUsage(List.of(KeyUsage.SIGN));
        profile = tokenProfileRepository.save(profile);
        key = new CryptographicKey();
        key.setName("legacy-key");
        key.setTokenProfile(profile);
        key.setTokenInstanceReference(token);
        key = cryptographicKeyRepository.save(key);
        privateKey = new CryptographicKeyItem();
        privateKey.setKey(key);
        privateKey.setKeyUuid(key.getUuid());
        privateKey.setType(KeyType.PRIVATE_KEY);
        privateKey.setKeyAlgorithm(KeyAlgorithm.RSA);
        privateKey.setFormat(KeyFormat.PRKI);
        privateKey.setLength(2048);
        privateKey.setState(KeyState.ACTIVE);
        privateKey.setEnabled(true);
        privateKey.setUsage(List.of(KeyUsage.SIGN));
        privateKey.setKeyReferenceUuid(UUID.randomUUID());
        privateKey = cryptographicKeyItemRepository.save(privateKey);
    }

    @Test
    void signData_callsAdapterWithoutActiveTransaction() throws Exception {
        // given
        AtomicBoolean transactionActive = new AtomicBoolean(true);
        KeyProviderAdapter adapter = mock(KeyProviderAdapter.class);
        when(keyProviderAdapterFactory.forKeyItem(any())).thenReturn(adapter);
        when(adapter.signData(any(), any())).thenAnswer(invocation -> {
            transactionActive.set(TransactionSynchronizationManager.isActualTransactionActive());
            return new SignDataResponseDto();
        });
        SignDataRequestDto request = new SignDataRequestDto();
        request.setSignatureAttributes(List.of());
        SignatureRequestData item = new SignatureRequestData();
        item.setData("AQ==");
        request.setData(List.of(item));

        // when
        operationService
                .signData(token.getSecuredParentUuid(), profile.getSecuredUuid(), key.getUuid(), privateKey.getUuid(),
                        request);

        // then
        assertFalse(transactionActive.get());
    }

    @Test
    void randomData_callsAdapterWithoutActiveTransaction() throws Exception {
        // given
        AtomicBoolean transactionActive = new AtomicBoolean(true);
        TokenProviderAdapter adapter = mock(TokenProviderAdapter.class);
        when(tokenProviderAdapterFactory.forToken(any(TokenInstanceBasicModel.class))).thenReturn(adapter);
        when(adapter.randomData(any(), any(), any())).thenAnswer(invocation -> {
            transactionActive.set(TransactionSynchronizationManager.isActualTransactionActive());
            return new RandomDataResponseDto();
        });
        RandomDataRequestDto request = new RandomDataRequestDto();
        request.setLength(4);
        request.setAttributes(List.of());

        // when
        operationService.randomData(token.getSecuredUuid(), request);

        // then
        assertFalse(transactionActive.get());
    }

    @Test
    void everyServiceOperation_declaresThatItSuspendsTheTransaction() {
        // when
        List<String> missing = Arrays
                .stream(CryptographicOperationServiceImpl.class.getDeclaredMethods())
                .filter(method -> Modifier.isPublic(method.getModifiers()) && !method.isSynthetic())
                .filter(CryptographicOperationServiceTransactionITest::isServiceOperation)
                .filter(method -> !suspendsTransaction(method))
                .map(Method::toString)
                .toList();

        // then
        assertTrue(missing.isEmpty(), "Methods without @Transactional(NOT_SUPPORTED): " + missing);
    }

    /** Setters are wiring. */
    private static boolean isServiceOperation(Method method) {
        return !method.getName().startsWith("set");
    }

    private static boolean suspendsTransaction(Method method) {
        Transactional transactional = method.getAnnotation(Transactional.class);
        return transactional != null && transactional.propagation() == Propagation.NOT_SUPPORTED;
    }
}

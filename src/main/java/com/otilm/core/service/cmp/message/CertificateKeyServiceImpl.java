package com.otilm.core.service.cmp.message;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.client.v1.CryptographicOperationsSyncApiClient;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.*;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.provider.PlatformProvider;
import com.otilm.core.provider.key.PlatformPrivateKey;
import com.otilm.core.service.CryptographicKeyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class CertificateKeyServiceImpl implements CertificateKeyService {

    private ConnectorApiFactory connectorApiFactory;

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    private CryptographicKeyService cryptographicKeyService;

    @Autowired
    public void setCryptographicKeyService(CryptographicKeyService cryptographicKeyService) {
        this.cryptographicKeyService = cryptographicKeyService;
    }

    @Override
    public PlatformProvider getProvider(String cmpProfileName, Certificate signingCertificate) throws NotFoundException {
        CryptographicKey key = signingCertificate.getKey();
        if (key == null) {
            throw new IllegalStateException("Signing certificate has no associated cryptographic key");
        }
        TokenInstanceReference tokenRef = key.getTokenInstanceReference();
        if (tokenRef == null) {
            throw new IllegalStateException("Cryptographic key has no token instance reference");
        }
        UUID connectorUuid = tokenRef.getConnectorUuid();
        if (connectorUuid == null) {
            throw new IllegalStateException("Token instance has no associated connector");
        }

        CryptographicOperationsSyncApiClient apiClient = connectorApiFactory.getCryptographicOperationsApiClient(connectorUuid);
        return PlatformProvider.getInstance(cmpProfileName, true, apiClient);
    }

    @Override
    public PlatformPrivateKey getPrivateKey(Certificate certificate) {
        CryptographicKey key = certificate.getKey();
        CryptographicKeyItem item = cryptographicKeyService.getKeyItemFromKey(key, KeyType.PRIVATE_KEY);
        TokenInstanceReference tokenInsReference = key.getTokenInstanceReference();
        return new PlatformPrivateKey(
                tokenInsReference.getTokenInstanceUuid(),
                item.getKeyReferenceUuid().toString(),
                tokenInsReference.getConnector().mapToDto(),
                item.getKeyAlgorithm().getLabel()
        );
    }

}

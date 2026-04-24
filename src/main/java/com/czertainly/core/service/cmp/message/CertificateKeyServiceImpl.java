package com.czertainly.core.service.cmp.message;

import com.czertainly.api.interfaces.client.v1.CryptographicOperationsSyncApiClient;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.provider.CzertainlyProvider;
import com.czertainly.core.provider.key.CzertainlyPrivateKey;
import com.czertainly.core.service.CryptographicKeyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

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
    public CzertainlyProvider getProvider(String cmpProfileName, Certificate signingCertificate) {
        CryptographicKey key = signingCertificate.getKey();
        if (key == null) {
            throw new IllegalStateException("Signing certificate has no associated cryptographic key");
        }
        TokenInstanceReference tokenRef = key.getTokenInstanceReference();
        if (tokenRef == null) {
            throw new IllegalStateException("Cryptographic key has no token instance reference");
        }
        Connector connector = tokenRef.getConnector();
        if (connector == null) {
            throw new IllegalStateException("Token instance has no associated connector");
        }

        var connectorDto = connector.mapToApiClientDtoV1();
        CryptographicOperationsSyncApiClient apiClient = connectorApiFactory.getCryptographicOperationsApiClient(connectorDto);
        return CzertainlyProvider.getInstance(cmpProfileName, true, apiClient);
    }

    @Override
    public CzertainlyPrivateKey getPrivateKey(Certificate certificate) {
        CryptographicKey key = certificate.getKey();
        CryptographicKeyItem item = cryptographicKeyService.getKeyItemFromKey(key, KeyType.PRIVATE_KEY);
        TokenInstanceReference tokenInsReference = key.getTokenInstanceReference();
        return new CzertainlyPrivateKey(
                tokenInsReference.getTokenInstanceUuid(),
                item.getKeyReferenceUuid().toString(),
                tokenInsReference.getConnector().mapToDto(),
                item.getKeyAlgorithm().getLabel()
        );
    }

}

package com.otilm.core.service.cmp.message;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.provider.PlatformProvider;
import com.otilm.core.provider.key.PlatformPrivateKey;
import com.otilm.core.service.CryptographicKeyInternalService;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import java.util.Objects;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CertificateKeyServiceImpl implements CertificateKeyService {

    private KeyProviderAdapterFactory keyProviderAdapterFactory;

    @Autowired
    public void setKeyProviderAdapterFactory(KeyProviderAdapterFactory keyProviderAdapterFactory) {
        this.keyProviderAdapterFactory = Objects
                .requireNonNull(keyProviderAdapterFactory, "keyProviderAdapterFactory must not be null");
    }

    private CryptographicKeyInternalService cryptographicKeyService;

    @Autowired
    public void setCryptographicKeyInternalService(CryptographicKeyInternalService cryptographicKeyService) {
        this.cryptographicKeyService = cryptographicKeyService;
    }

    @Override
    public PlatformProvider getProvider(String cmpProfileName, Certificate signingCertificate)
            throws NotFoundException {
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

        return PlatformProvider.getInstance(cmpProfileName, true, keyProviderAdapterFactory);
    }

    @Override
    public PlatformPrivateKey getPrivateKey(Certificate certificate) throws NotFoundException {
        CryptographicKey key = certificate.getKey();
        CryptographicKeyItem item = cryptographicKeyService.getKeyItemFromKey(key, KeyType.PRIVATE_KEY);
        return new PlatformPrivateKey(cryptographicKeyService.getKeyItemModel(item.getUuid()));
    }

}

package com.otilm.core.provider;

import com.otilm.api.interfaces.client.v1.CryptographicOperationsSyncApiClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Provider;
import java.security.Security;

/**
 * JCA provider for cryptographic operations using Cryptographic Provider interface.
 */
public class PlatformProvider extends Provider {

    public static final String PROVIDER_NAME = "PlatformProvider";
    private static final Logger logger = LoggerFactory.getLogger(PlatformProvider.class);

    private PlatformProvider(String name, CryptographicOperationsSyncApiClient apiClient) {
        super(name, "1.0", "CZERTAINLY Provider");
        this.init(apiClient);
    }

    public static PlatformProvider getInstance(String name, boolean registerProvider, CryptographicOperationsSyncApiClient apiClient) {
        String instanceName = "%s-%s".formatted(PROVIDER_NAME, name);
        PlatformProvider provider = new PlatformProvider(instanceName, apiClient);

        if (registerProvider) {
            if (Security.getProvider(provider.getName()) != null) {
                logger.info("Provider {} already registered.", provider.getName());
            } else {
                Security.addProvider(provider);
                logger.info("Provider {} registered.", provider.getName());
            }
        }

        return provider;
    }

    void init(CryptographicOperationsSyncApiClient apiClient) {
        this.setupServices(apiClient);
    }

    void setupServices(CryptographicOperationsSyncApiClient apiClient) {
        // Register Cipher algorithms for encryption and decryption
        putService(new PlatformCipherProviderService(this, "Cipher", new PlatformCipherService(apiClient, "RSA")));
        putService(new PlatformCipherProviderService(this, "Cipher", new PlatformCipherService(apiClient, "RSA/ECB/PKCS1Padding")));
        putService(new PlatformCipherProviderService(this, "Cipher", new PlatformCipherService(apiClient, "RSA/NONE/PKCS1Padding")));

        // Register Signature algorithms for signing and verification
        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "NONEwithRSA")));
        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "MD5withRSA")));
        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "SHA1withRSA")));
        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "SHA224withRSA")));
        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "SHA256withRSA")));
        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "SHA384withRSA")));
        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "SHA512withRSA")));

        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "NONEwithRSA/PSS")));
        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "SHA1withRSA/PSS")));
        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "SHA224withRSA/PSS")));
        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "SHA256withRSA/PSS")));
        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "SHA384withRSA/PSS")));
        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "SHA512withRSA/PSS")));

        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "NONEwithECDSA")));
        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "SHA1withECDSA")));
        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "SHA224withECDSA")));
        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "SHA256withECDSA")));
        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "SHA384withECDSA")));
        putService(new PlatformSignatureProviderService(this, "Signature", new PlatformSignatureService(apiClient, "SHA512withECDSA")));
    }
}
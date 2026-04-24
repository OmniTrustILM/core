package com.czertainly.core.provider;

import com.czertainly.api.interfaces.client.v1.CryptographicOperationsSyncApiClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Provider;
import java.security.Security;

/**
 * JCA provider for cryptographic operations using Cryptographic Provider interface.
 */
public class CzertainlyProvider extends Provider {

    public static final String PROVIDER_NAME = "CzertainlyProvider";
    private static final Logger logger = LoggerFactory.getLogger(CzertainlyProvider.class);

    private CzertainlyProvider(String name, CryptographicOperationsSyncApiClient apiClient) {
        super(name, "1.0", "CZERTAINLY Provider");
        this.init(apiClient);
    }

    public static CzertainlyProvider getInstance(String name, boolean registerProvider, CryptographicOperationsSyncApiClient apiClient) {
        String instanceName = "%s-%s".formatted(PROVIDER_NAME, name);
        CzertainlyProvider provider = new CzertainlyProvider(instanceName, apiClient);

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
        putService(new CzertainlyCipherProviderService(this, "Cipher", new CzertainlyCipherService(apiClient, "RSA")));
        putService(new CzertainlyCipherProviderService(this, "Cipher", new CzertainlyCipherService(apiClient, "RSA/ECB/PKCS1Padding")));
        putService(new CzertainlyCipherProviderService(this, "Cipher", new CzertainlyCipherService(apiClient, "RSA/NONE/PKCS1Padding")));

        // Register Signature algorithms for signing and verification
        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "NONEwithRSA")));
        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "MD5withRSA")));
        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "SHA1withRSA")));
        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "SHA224withRSA")));
        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "SHA256withRSA")));
        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "SHA384withRSA")));
        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "SHA512withRSA")));

        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "NONEwithRSA/PSS")));
        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "SHA1withRSA/PSS")));
        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "SHA224withRSA/PSS")));
        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "SHA256withRSA/PSS")));
        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "SHA384withRSA/PSS")));
        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "SHA512withRSA/PSS")));

        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "NONEwithECDSA")));
        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "SHA1withECDSA")));
        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "SHA224withECDSA")));
        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "SHA256withECDSA")));
        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "SHA384withECDSA")));
        putService(new CzertainlySignatureProviderService(this, "Signature", new CzertainlySignatureService(apiClient, "SHA512withECDSA")));
    }
}
package com.otilm.core.provider;

import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import java.security.Provider;
import java.security.Security;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JCA provider for cryptographic operations using Cryptographic Provider interface.
 */
public class PlatformProvider extends Provider {

    public static final String PROVIDER_NAME = "PlatformProvider";
    private static final Logger logger = LoggerFactory.getLogger(PlatformProvider.class);

    private PlatformProvider(String name, KeyProviderAdapterFactory adapterFactory) {
        super(name, "1.0", "Platform Provider");
        this.init(Objects.requireNonNull(adapterFactory, "adapterFactory must not be null"));
    }

    public static PlatformProvider getInstance(String name, boolean registerProvider,
            KeyProviderAdapterFactory adapterFactory) {
        Objects.requireNonNull(name, "name must not be null");
        String instanceName = "%s-%s".formatted(PROVIDER_NAME, name);
        PlatformProvider provider = new PlatformProvider(instanceName, adapterFactory);

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

    void init(KeyProviderAdapterFactory adapterFactory) {
        this.setupServices(adapterFactory);
    }

    void setupServices(KeyProviderAdapterFactory adapterFactory) {
        // Register Cipher algorithms for encryption and decryption
        putService(new PlatformCipherProviderService(this, "Cipher", new PlatformCipherService(adapterFactory, "RSA")));
        putService(new PlatformCipherProviderService(this, "Cipher",
                new PlatformCipherService(adapterFactory, "RSA/ECB/PKCS1Padding")));
        putService(new PlatformCipherProviderService(this, "Cipher",
                new PlatformCipherService(adapterFactory, "RSA/NONE/PKCS1Padding")));

        // Register Signature algorithms for signing and verification
        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "NONEwithRSA")));
        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "MD5withRSA")));
        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "SHA1withRSA")));
        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "SHA224withRSA")));
        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "SHA256withRSA")));
        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "SHA384withRSA")));
        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "SHA512withRSA")));

        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "NONEwithRSA/PSS")));
        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "SHA1withRSA/PSS")));
        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "SHA224withRSA/PSS")));
        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "SHA256withRSA/PSS")));
        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "SHA384withRSA/PSS")));
        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "SHA512withRSA/PSS")));

        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "NONEwithECDSA")));
        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "SHA1withECDSA")));
        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "SHA224withECDSA")));
        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "SHA256withECDSA")));
        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "SHA384withECDSA")));
        putService(new PlatformSignatureProviderService(this, "Signature",
                new PlatformSignatureService(adapterFactory, "SHA512withECDSA")));
    }
}

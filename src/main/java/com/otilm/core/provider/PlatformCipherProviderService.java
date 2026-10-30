package com.otilm.core.provider;

import com.otilm.core.provider.spi.PlatformCipherSpi;

import java.security.Provider;

public class PlatformCipherProviderService extends Provider.Service {

    private final PlatformCipherService cipherService;

    public PlatformCipherProviderService(Provider provider, String type, PlatformCipherService cipherService) {
        super(provider, type, cipherService.getAlgorithm(), PlatformCipherSpi.class.getName(), null, null);
        this.cipherService = cipherService;
    }

    @Override
    public Object newInstance(Object constructorParameter) {
        return new PlatformCipherSpi(this.cipherService);
    }
}

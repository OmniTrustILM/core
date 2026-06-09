package com.otilm.core.provider;

import com.otilm.core.provider.spi.CzertainlyCipherSpi;

import java.security.Provider;

public class CzertainlyCipherProviderService extends Provider.Service {

    private final CzertainlyCipherService cipherService;

    public CzertainlyCipherProviderService(Provider provider, String type, CzertainlyCipherService cipherService) {
        super(provider, type, cipherService.getAlgorithm(), CzertainlyCipherSpi.class.getName(), null, null);
        this.cipherService = cipherService;
    }

    @Override
    public Object newInstance(Object constructorParameter) {
        return new CzertainlyCipherSpi(this.cipherService);
    }
}

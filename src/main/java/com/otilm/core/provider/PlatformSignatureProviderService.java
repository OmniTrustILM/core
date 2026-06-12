package com.otilm.core.provider;

import com.otilm.core.provider.spi.PlatformSignatureSpi;

import java.security.Provider;

public class PlatformSignatureProviderService extends Provider.Service {

    private final PlatformSignatureService signatureService;

    public PlatformSignatureProviderService(Provider provider, String type, PlatformSignatureService signatureService) {
        super(provider, type, signatureService.getAlgorithm(), PlatformSignatureSpi.class.getName(), null, null);
        this.signatureService = signatureService;
    }

    @Override
    public Object newInstance(Object constructorParameter) {
        return new PlatformSignatureSpi(this.signatureService);
    }


}

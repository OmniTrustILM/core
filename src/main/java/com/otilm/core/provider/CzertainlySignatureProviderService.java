package com.otilm.core.provider;

import com.otilm.core.provider.spi.CzertainlySignatureSpi;

import java.security.Provider;

public class CzertainlySignatureProviderService extends Provider.Service {

    private final CzertainlySignatureService signatureService;

    public CzertainlySignatureProviderService(Provider provider, String type, CzertainlySignatureService signatureService) {
        super(provider, type, signatureService.getAlgorithm(), CzertainlySignatureSpi.class.getName(), null, null);
        this.signatureService = signatureService;
    }

    @Override
    public Object newInstance(Object constructorParameter) {
        return new CzertainlySignatureSpi(this.signatureService);
    }


}

package com.otilm.core.util.builders;

import com.otilm.core.dao.entity.Crl;

import java.util.Date;
import java.util.UUID;

/**
 * Builds an in-memory {@link Crl}; tests override only the fields whose values drive the assertion under
 * test. Persistence goes through {@code CrlRepository}, not this builder. {@code nextUpdate} defaults to
 * "now" so the common case need not set it.
 */
public class CrlBuilder {

    private UUID caCertificateUuid;
    private String issuerDn;
    private String serialNumber;
    private String crlIssuerDn;
    private String crlNumber;
    private Date nextUpdate = new Date();

    public static CrlBuilder aCrl() {
        return new CrlBuilder();
    }

    public CrlBuilder withCaCertificateUuid(UUID caCertificateUuid) {
        this.caCertificateUuid = caCertificateUuid;
        return this;
    }

    public CrlBuilder withIssuerDn(String issuerDn) {
        this.issuerDn = issuerDn;
        return this;
    }

    public CrlBuilder withSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
        return this;
    }

    public CrlBuilder withCrlIssuerDn(String crlIssuerDn) {
        this.crlIssuerDn = crlIssuerDn;
        return this;
    }

    public CrlBuilder withCrlNumber(String crlNumber) {
        this.crlNumber = crlNumber;
        return this;
    }

    public Crl build() {
        Crl crl = new Crl();
        crl.setCaCertificateUuid(caCertificateUuid);
        crl.setIssuerDn(issuerDn);
        crl.setSerialNumber(serialNumber);
        crl.setCrlIssuerDn(crlIssuerDn);
        crl.setCrlNumber(crlNumber);
        crl.setNextUpdate(nextUpdate);
        return crl;
    }
}

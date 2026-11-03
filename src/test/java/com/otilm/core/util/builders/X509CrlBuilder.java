package com.otilm.core.util.builders;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Builds a CRL that {@code signerKey}, an RSA key, signs under {@code issuerName}. By default it is a base CRL with CRL
 * number 1, issued an hour ago with its next update in a week, that lists no certificate.
 */
public final class X509CrlBuilder {

    private final X500Principal issuerName;

    private final PrivateKey signerKey;

    private BigInteger crlNumber = BigInteger.ONE;

    private Instant nextUpdate = Instant.now().plus(Duration.ofDays(7));

    private BigInteger deltaCrlIndicator;

    private final Map<BigInteger, Integer> revocations = new LinkedHashMap<>();

    private X509CrlBuilder(X500Principal issuerName, PrivateKey signerKey) {
        this.issuerName = issuerName;
        this.signerKey = signerKey;
    }

    public static X509CrlBuilder anX509Crl(X500Principal issuerName, PrivateKey signerKey) {
        return new X509CrlBuilder(issuerName, signerKey);
    }

    /** {@code null} leaves the CRL number extension out. */
    public X509CrlBuilder withCrlNumber(BigInteger crlNumber) {
        this.crlNumber = crlNumber;
        return this;
    }

    /** {@code null} leaves the next update out. */
    public X509CrlBuilder withNextUpdate(Instant nextUpdate) {
        this.nextUpdate = nextUpdate;
        return this;
    }

    /** Makes it a delta CRL on the base CRL with this number. */
    public X509CrlBuilder withDeltaCrlIndicator(BigInteger baseCrlNumber) {
        this.deltaCrlIndicator = baseCrlNumber;
        return this;
    }

    /** Lists the serial number as revoked now, for a {@link CRLReason} code. */
    public X509CrlBuilder withRevocation(BigInteger serialNumber, int reason) {
        revocations.put(serialNumber, reason);
        return this;
    }

    public X509CRL build() {
        try {
            Date thisUpdate = Date.from(Instant.now().minus(Duration.ofHours(1)));
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(X500Name.getInstance(issuerName.getEncoded()),
                    thisUpdate);
            if (nextUpdate != null) {
                crlBuilder.setNextUpdate(Date.from(nextUpdate));
            }
            if (crlNumber != null) {
                crlBuilder.addExtension(Extension.cRLNumber, false, new CRLNumber(crlNumber));
            }
            if (deltaCrlIndicator != null) {
                crlBuilder.addExtension(Extension.deltaCRLIndicator, true, new CRLNumber(deltaCrlIndicator));
            }
            for (Map.Entry<BigInteger, Integer> revocation : revocations.entrySet()) {
                ExtensionsGenerator entryExtensions = new ExtensionsGenerator();
                entryExtensions.addExtension(Extension.reasonCode, false, CRLReason.lookup(revocation.getValue()));
                crlBuilder.addCRLEntry(revocation.getKey(), new Date(), entryExtensions.generate());
            }
            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(signerKey);
            return new JcaX509CRLConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCRL(crlBuilder.build(signer));
        } catch (IOException | OperatorCreationException | CRLException e) {
            throw new IllegalStateException("Failed to build the CRL", e);
        }
    }
}

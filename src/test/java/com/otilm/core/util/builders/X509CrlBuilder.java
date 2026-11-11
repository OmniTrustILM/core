package com.otilm.core.util.builders;

import java.io.IOException;
import java.io.OutputStream;
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
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Builds a CRL that {@code signerKey} signs under {@code issuerName}. By default it is a base CRL with CRL number 1,
 * issued an hour ago with its next update in a week, that lists no certificate and is signed with SHA-256 and RSA, so
 * the key must be an RSA key unless {@link #withSignatureAlgorithm} names another algorithm.
 */
public final class X509CrlBuilder {

    private final X500Principal issuerName;

    private final PrivateKey signerKey;

    private BigInteger crlNumber = BigInteger.ONE;

    private final Instant thisUpdate = Instant.now().minus(Duration.ofHours(1));

    private Instant nextUpdate = Instant.now().plus(Duration.ofDays(7));

    private BigInteger deltaCrlIndicator;

    private String signatureAlgorithm = "SHA256WithRSAEncryption";

    private ASN1Encodable signatureAlgorithmParameters;

    private final Map<BigInteger, Revocation> revocations = new LinkedHashMap<>();

    private final Map<ASN1ObjectIdentifier, ASN1Encodable> extraExtensions = new LinkedHashMap<>();

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
        return withRevocation(serialNumber, reason, Instant.now());
    }

    /** Lists the serial number as revoked at {@code revocationDate}, for a {@link CRLReason} code. */
    public X509CrlBuilder withRevocation(BigInteger serialNumber, int reason, Instant revocationDate) {
        ExtensionsGenerator entryExtensions = new ExtensionsGenerator();
        try {
            entryExtensions.addExtension(Extension.reasonCode, false, CRLReason.lookup(reason));
        } catch (IOException e) {
            throw new IllegalStateException("Failed to encode the reason code", e);
        }
        return withRevocation(serialNumber, revocationDate, entryExtensions.generate());
    }

    /** Lists the serial number as revoked at {@code revocationDate} with these entry extensions, or none for null. */
    public X509CrlBuilder withRevocation(BigInteger serialNumber, Instant revocationDate, Extensions extensions) {
        revocations.put(serialNumber, new Revocation(extensions, revocationDate));
        return this;
    }

    /** Adds a non-critical CRL extension besides the CRL number and the delta CRL indicator. */
    public X509CrlBuilder withExtension(ASN1ObjectIdentifier extensionId, ASN1Encodable value) {
        extraExtensions.put(extensionId, value);
        return this;
    }

    /** Signs with this JCA signature algorithm, which must suit the signer key. */
    public X509CrlBuilder withSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    /** Encodes these parameters with the signature algorithm in place of the ones the algorithm itself uses. */
    public X509CrlBuilder withSignatureAlgorithmParameters(ASN1Encodable signatureAlgorithmParameters) {
        this.signatureAlgorithmParameters = signatureAlgorithmParameters;
        return this;
    }

    public X509CRL build() {
        try {
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(X500Name.getInstance(issuerName.getEncoded()),
                    Date.from(thisUpdate));
            if (nextUpdate != null) {
                crlBuilder.setNextUpdate(Date.from(nextUpdate));
            }
            if (crlNumber != null) {
                crlBuilder.addExtension(Extension.cRLNumber, false, new CRLNumber(crlNumber));
            }
            if (deltaCrlIndicator != null) {
                crlBuilder.addExtension(Extension.deltaCRLIndicator, true, new CRLNumber(deltaCrlIndicator));
            }
            for (Map.Entry<ASN1ObjectIdentifier, ASN1Encodable> extension : extraExtensions.entrySet()) {
                crlBuilder.addExtension(extension.getKey(), false, extension.getValue());
            }
            for (Map.Entry<BigInteger, Revocation> revocation : revocations.entrySet()) {
                crlBuilder
                        .addCRLEntry(revocation.getKey(), Date.from(revocation.getValue().revocationDate()),
                                revocation.getValue().extensions());
            }
            ContentSigner algorithmSigner = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(signerKey);
            ContentSigner signer = signatureAlgorithmParameters == null
                    ? algorithmSigner
                    : withParameters(algorithmSigner, signatureAlgorithmParameters);
            return new JcaX509CRLConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCRL(crlBuilder.build(signer));
        } catch (IOException | OperatorCreationException | CRLException e) {
            throw new IllegalStateException("Failed to build the CRL", e);
        }
    }

    /** Signs as the signer does, naming its algorithm with the given parameters. */
    private static ContentSigner withParameters(ContentSigner signer, ASN1Encodable parameters) {
        AlgorithmIdentifier algorithm = new AlgorithmIdentifier(signer.getAlgorithmIdentifier().getAlgorithm(),
                parameters);
        return new ContentSigner() {
            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return algorithm;
            }

            @Override
            public OutputStream getOutputStream() {
                return signer.getOutputStream();
            }

            @Override
            public byte[] getSignature() {
                return signer.getSignature();
            }
        };
    }

    private record Revocation(Extensions extensions, Instant revocationDate) {
    }
}

package com.otilm.core.util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * A small PKI for client certificate tests: certificate authorities, the certificates they issue, and the CRLs and OCSP
 * requests about those certificates. Keys are EC P-256, every certificate has a random serial number and is valid from
 * a minute ago for a year unless its factory says otherwise, and a certificate names only the revocation sources it is
 * given.
 */
public final class PkiFixtures {

    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
    private static final String CURVE = "secp256r1";
    private static final Duration VALIDITY = Duration.ofDays(365);
    private static final Duration CLOCK_LEEWAY = Duration.ofMinutes(1);
    private static final Duration CRL_VALIDITY = Duration.ofDays(1);
    private static final SecureRandom RANDOM = new SecureRandom();

    /** The number of every CRL that {@link #crl} builds. */
    public static final BigInteger CRL_NUMBER = BigInteger.ONE;

    /** The subject of every client certificate that a factory builds without being given one. */
    public static final String CLIENT_SUBJECT = "CN=EST client";

    private PkiFixtures() {
    }

    /** A certificate authority: the key pair it signs with and its certificate. */
    public record Ca(KeyPair keyPair, X509Certificate certificate) {
    }

    /**
     * Where a certificate says its revocation status is published, and where its issuer's certificate is.
     *
     * @param ocspUrls the OCSP responders of its authority information access extension
     * @param ocspDirectoryNames the directory names of OCSP responders in that extension, which name no URI
     * @param caIssuerUrls where that extension says the certificate of the issuer is published
     * @param crlUrls the URIs of its CRL distribution points
     * @param crlDirectoryNames the directory names of its CRL distribution points, which name no URI
     * @param deltaCrlUrls the URIs of its freshest CRL extension, where delta CRLs are published
     */
    public record RevocationSources(List<String> ocspUrls, List<String> ocspDirectoryNames, List<String> caIssuerUrls,
            List<String> crlUrls, List<String> crlDirectoryNames, List<String> deltaCrlUrls) {

        public static final RevocationSources NONE = new RevocationSources(List.of(), List.of(), List.of(), List.of(),
                List.of(), List.of());

        public static RevocationSources ocsp(String url) {
            return new RevocationSources(List.of(url), List.of(), List.of(), List.of(), List.of(), List.of());
        }

        /** An OCSP responder that the authority information access extension names by a directory entry. */
        public static RevocationSources ocspInDirectory(String directoryName) {
            return new RevocationSources(List.of(), List.of(directoryName), List.of(), List.of(), List.of(), List.of());
        }

        /** An authority information access extension that names no OCSP responder, only the issuer's certificate. */
        public static RevocationSources onlyCaIssuers(String url) {
            return new RevocationSources(List.of(), List.of(), List.of(url), List.of(), List.of(), List.of());
        }

        public static RevocationSources crl(String url) {
            return new RevocationSources(List.of(), List.of(), List.of(), List.of(url), List.of(), List.of());
        }

        public static RevocationSources ocspAndCrl(String ocspUrl, String crlUrl) {
            return new RevocationSources(List.of(ocspUrl), List.of(), List.of(), List.of(crlUrl), List.of(), List.of());
        }

        public static RevocationSources crlAndDeltaCrl(String crlUrl, String deltaCrlUrl) {
            return new RevocationSources(List.of(), List.of(), List.of(), List.of(crlUrl), List.of(),
                    List.of(deltaCrlUrl));
        }

        /** A freshest CRL extension without a CRL distribution point to which its delta CRLs apply. */
        public static RevocationSources onlyDeltaCrl(String deltaCrlUrl) {
            return new RevocationSources(List.of(), List.of(), List.of(), List.of(), List.of(), List.of(deltaCrlUrl));
        }

        /** A CRL distribution point that names a directory entry instead of a URI. */
        public static RevocationSources crlInDirectory(String directoryName) {
            return new RevocationSources(List.of(), List.of(), List.of(), List.of(), List.of(directoryName), List.of());
        }
    }

    public static KeyPair keyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(CURVE));
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("The test key pair cannot be generated", e);
        }
    }

    /** A self-signed root CA. */
    public static Ca rootCa(String commonName) {
        KeyPair keyPair = keyPair();
        X500Name name = new X500Name("CN=" + commonName);
        X509Certificate certificate = issue(name, keyPair, name, keyPair.getPublic(), Usage.CA, validNow(),
                RevocationSources.NONE, List.of());
        return new Ca(keyPair, certificate);
    }

    /** A CA that the issuer certified, naming no revocation source. */
    public static Ca intermediateCa(Ca issuer, String commonName) {
        return intermediateCa(issuer, commonName, RevocationSources.NONE);
    }

    /** A CA that the issuer certified, naming the revocation sources. */
    public static Ca intermediateCa(Ca issuer, String commonName, RevocationSources sources) {
        return issueSigner(issuer, commonName, Usage.CA, validNow(), sources);
    }

    /** A CA that the issuer certified, naming no revocation source, whose validity ended a day ago. */
    public static Ca expiredIntermediateCa(Ca issuer, String commonName) {
        return issueSigner(issuer, commonName, Usage.CA, endedADayAgo(), RevocationSources.NONE);
    }

    /**
     * An end-entity certificate that the issuer certified, with its key pair, so that certificates can be issued under
     * it: its key usage allows certificate signing, but its basic constraints deny it a CA.
     */
    public static Ca endEntityIssuer(Ca issuer, String commonName) {
        return issueSigner(issuer, commonName, Usage.END_ENTITY_ISSUER, validNow(), RevocationSources.NONE);
    }

    /** A certificate for TLS client authentication: its only extended key usage is clientAuth. */
    public static X509Certificate clientCertificate(Ca issuer) {
        return clientCertificate(issuer, RevocationSources.NONE);
    }

    /** A certificate for TLS client authentication that names the revocation sources. */
    public static X509Certificate clientCertificate(Ca issuer, RevocationSources sources) {
        return issueEndEntity(issuer, Usage.CLIENT, validNow(), sources);
    }

    /**
     * A certificate for TLS client authentication of the subject, with the names as its subject alternative names when
     * there are any. The subject is written as {@link X500Name} reads it, so a value with a separator is escaped.
     */
    public static X509Certificate clientCertificateFor(Ca issuer, String subject, GeneralName... alternativeNames) {
        return issue(subjectOf(issuer), issuer.keyPair(), new X500Name(subject), keyPair().getPublic(), Usage.CLIENT,
                validNow(), RevocationSources.NONE, List.of(alternativeNames));
    }

    /**
     * A certificate for TLS client authentication of the subject that certifies the key pair's public key, valid
     * between the instants, with the names as its subject alternative names when there are any.
     */
    public static X509Certificate clientCertificateFor(Ca issuer, KeyPair subjectKeys, Instant notBefore,
            Instant notAfter, String subject, GeneralName... alternativeNames) {
        return issue(subjectOf(issuer), issuer.keyPair(), new X500Name(subject), subjectKeys.getPublic(), Usage.CLIENT,
                new Validity(notBefore, notAfter), RevocationSources.NONE, List.of(alternativeNames));
    }

    /**
     * A certificate for TLS client authentication whose authority information access extension holds the value, which
     * need not be the SEQUENCE that the extension is defined as. It names no other revocation source.
     */
    public static X509Certificate clientCertificateWithAuthorityInfoAccess(Ca issuer, ASN1Encodable value) {
        return clientCertificateWithAuthorityInfoAccess(issuer, value, RevocationSources.NONE);
    }

    /**
     * A certificate for TLS client authentication whose authority information access extension holds the value, which
     * need not be the SEQUENCE that the extension is defined as, and that names the revocation sources besides. The
     * sources must not name an OCSP responder, since its access description would be a second extension of that kind.
     */
    public static X509Certificate clientCertificateWithAuthorityInfoAccess(Ca issuer, ASN1Encodable value,
            RevocationSources sources) {
        try {
            Extension authorityInfoAccess = new Extension(Extension.authorityInfoAccess, false,
                    value.toASN1Primitive().getEncoded(ASN1Encoding.DER));
            return issue(subjectOf(issuer), issuer.keyPair(), new X500Name(CLIENT_SUBJECT), keyPair().getPublic(),
                    Usage.CLIENT, validNow(), sources, List.of(), List.of(authorityInfoAccess));
        } catch (IOException e) {
            throw new IllegalStateException("The test certificate cannot be issued", e);
        }
    }

    /** A certificate of an EST RA: its extended key usages are clientAuth and id-kp-cmcRA. */
    public static X509Certificate raCertificate(Ca issuer) {
        return issueEndEntity(issuer, Usage.RA, validNow(), RevocationSources.NONE);
    }

    /** A certificate for TLS servers: its only extended key usage is serverAuth. */
    public static X509Certificate serverCertificate(Ca issuer) {
        return issueEndEntity(issuer, Usage.SERVER, validNow(), RevocationSources.NONE);
    }

    /** A certificate without the extended key usage extension, which leaves every purpose open. */
    public static X509Certificate certificateWithoutExtendedKeyUsage(Ca issuer) {
        return issueEndEntity(issuer, Usage.ANY, validNow(), RevocationSources.NONE);
    }

    /** A certificate for TLS client authentication whose validity ended a day ago. */
    public static X509Certificate expiredClientCertificate(Ca issuer) {
        return issueEndEntity(issuer, Usage.CLIENT, endedADayAgo(), RevocationSources.NONE);
    }

    /** A self-signed certificate for TLS client authentication, which is no CA. */
    public static X509Certificate selfSignedClientCertificate() {
        KeyPair keyPair = keyPair();
        X500Name name = new X500Name(CLIENT_SUBJECT);
        return issue(name, keyPair, name, keyPair.getPublic(), Usage.CLIENT, validNow(), RevocationSources.NONE,
                List.of());
    }

    /** A CRL that the CA signed, current for a day, that lists the certificates as revoked. */
    public static byte[] crl(Ca issuer, X509Certificate... revoked) {
        CrlPeriod period = currentForADay();
        X509v2CRLBuilder builder = crlBuilder(issuer, period);
        for (X509Certificate certificate : revoked) {
            builder.addCRLEntry(certificate.getSerialNumber(), period.thisUpdate(), CRLReason.keyCompromise);
        }
        return signedCrl(builder, issuer, CRL_NUMBER, null);
    }

    /** A CRL that the CA signed and that lists nothing, whose next update was a day ago. */
    public static byte[] expiredCrl(Ca issuer) {
        return signedCrl(crlBuilder(issuer, expiredADayAgo()), issuer, CRL_NUMBER, null);
    }

    /**
     * A delta CRL that the CA signed, current for a day and listing nothing, which updates the CRL of the given number.
     */
    public static byte[] deltaCrl(Ca issuer, BigInteger baseCrlNumber) {
        return signedCrl(crlBuilder(issuer, currentForADay()), issuer, baseCrlNumber.add(BigInteger.ONE),
                baseCrlNumber);
    }

    /**
     * A delta CRL that the CA signed and that lists nothing, which updates the CRL of the given number and whose next
     * update was a day ago.
     */
    public static byte[] expiredDeltaCrl(Ca issuer, BigInteger baseCrlNumber) {
        return signedCrl(crlBuilder(issuer, expiredADayAgo()), issuer, baseCrlNumber.add(BigInteger.ONE),
                baseCrlNumber);
    }

    /** A CRL that the CA signed and that lists nothing, whose next update passed the given time ago. */
    public static byte[] crlExpiredFor(Ca issuer, Duration sinceNextUpdate) {
        return signedCrl(crlBuilder(issuer, expiredFor(sinceNextUpdate)), issuer, CRL_NUMBER, null);
    }

    /**
     * A delta CRL that the CA signed and that lists nothing, which updates the CRL of the given number and whose next
     * update passed the given time ago.
     */
    public static byte[] deltaCrlExpiredFor(Ca issuer, BigInteger baseCrlNumber, Duration sinceNextUpdate) {
        return signedCrl(crlBuilder(issuer, expiredFor(sinceNextUpdate)), issuer, baseCrlNumber.add(BigInteger.ONE),
                baseCrlNumber);
    }

    /**
     * A request for the status of the certificate, as Core makes one but without a nonce, so that a response built for
     * it answers every request Core sends about the certificate.
     */
    public static OCSPReq ocspRequest(X509Certificate certificate, X509Certificate issuer) {
        try {
            CertificateID certificateId = new CertificateID(
                    new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                    new JcaX509CertificateHolder(issuer), certificate.getSerialNumber());
            return new OCSPReqBuilder().addRequest(certificateId).build();
        } catch (OperatorCreationException | OCSPException | GeneralSecurityException e) {
            throw new IllegalStateException("The test OCSP request cannot be built", e);
        }
    }

    private static Ca issueSigner(Ca issuer, String commonName, Usage usage, Validity validity,
            RevocationSources sources) {
        KeyPair keyPair = keyPair();
        X509Certificate certificate = issue(issuer, new X500Name("CN=" + commonName), keyPair.getPublic(), usage,
                validity, sources);
        return new Ca(keyPair, certificate);
    }

    private static X509Certificate issueEndEntity(Ca issuer, Usage usage, Validity validity,
            RevocationSources sources) {
        return issue(issuer, new X500Name(CLIENT_SUBJECT), keyPair().getPublic(), usage, validity, sources);
    }

    private static X509Certificate issue(Ca issuer, X500Name subject, PublicKey subjectKey, Usage usage,
            Validity validity, RevocationSources sources) {
        return issue(subjectOf(issuer), issuer.keyPair(), subject, subjectKey, usage, validity, sources, List.of());
    }

    private static X509Certificate issue(X500Name issuer, KeyPair issuerKeyPair, X500Name subject, PublicKey subjectKey,
            Usage usage, Validity validity, RevocationSources sources, List<GeneralName> alternativeNames) {
        return issue(issuer, issuerKeyPair, subject, subjectKey, usage, validity, sources, alternativeNames, List.of());
    }

    private static X509Certificate issue(X500Name issuer, KeyPair issuerKeyPair, X500Name subject, PublicKey subjectKey,
            Usage usage, Validity validity, RevocationSources sources, List<GeneralName> alternativeNames,
            List<Extension> additionalExtensions) {
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, new BigInteger(64, RANDOM),
                Date.from(validity.notBefore()), Date.from(validity.notAfter()), subject, subjectKey);
        try {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(usage == Usage.CA));
            builder.addExtension(Extension.keyUsage, true, usage.keyUsage());
            if (usage.purposes().length > 0) {
                builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(usage.purposes()));
            }
            if (!alternativeNames.isEmpty()) {
                builder
                        .addExtension(Extension.subjectAlternativeName, false,
                                new GeneralNames(alternativeNames.toArray(GeneralName[]::new)));
            }
            List<AccessDescription> authorityAccess = authorityAccessOf(sources);
            if (!authorityAccess.isEmpty()) {
                builder
                        .addExtension(Extension.authorityInfoAccess, false,
                                new AuthorityInformationAccess(authorityAccess.toArray(AccessDescription[]::new)));
            }
            List<GeneralName> crlLocations = Stream
                    .concat(sources.crlUrls().stream().map(PkiFixtures::uri),
                            sources.crlDirectoryNames().stream().map(PkiFixtures::directoryName))
                    .toList();
            if (!crlLocations.isEmpty()) {
                builder.addExtension(Extension.cRLDistributionPoints, false, distributionPoints(crlLocations));
            }
            if (!sources.deltaCrlUrls().isEmpty()) {
                builder
                        .addExtension(Extension.freshestCRL, false,
                                distributionPoints(sources.deltaCrlUrls().stream().map(PkiFixtures::uri).toList()));
            }
            for (Extension extension : additionalExtensions) {
                builder.addExtension(extension);
            }
            return new JcaX509CertificateConverter().getCertificate(builder.build(signer(issuerKeyPair)));
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("The test certificate cannot be issued", e);
        }
    }

    private static List<AccessDescription> authorityAccessOf(RevocationSources sources) {
        Stream<GeneralName> ocspLocations = Stream
                .concat(sources.ocspUrls().stream().map(PkiFixtures::uri),
                        sources.ocspDirectoryNames().stream().map(PkiFixtures::directoryName));
        Stream<AccessDescription> responders = ocspLocations
                .map(location -> new AccessDescription(AccessDescription.id_ad_ocsp, location));
        Stream<AccessDescription> issuers = sources
                .caIssuerUrls()
                .stream()
                .map(url -> new AccessDescription(AccessDescription.id_ad_caIssuers, uri(url)));
        return Stream.concat(responders, issuers).toList();
    }

    private static CRLDistPoint distributionPoints(List<GeneralName> locations) {
        DistributionPoint[] points = locations
                .stream()
                .map(location -> new DistributionPoint(new DistributionPointName(new GeneralNames(location)), null,
                        null))
                .toArray(DistributionPoint[]::new);
        return new CRLDistPoint(points);
    }

    private static GeneralName uri(String url) {
        return new GeneralName(GeneralName.uniformResourceIdentifier, url);
    }

    private static GeneralName directoryName(String name) {
        return new GeneralName(new X500Name(name));
    }

    private static X500Name subjectOf(Ca ca) {
        return X500Name.getInstance(ca.certificate().getSubjectX500Principal().getEncoded());
    }

    private static X509v2CRLBuilder crlBuilder(Ca issuer, CrlPeriod period) {
        X509v2CRLBuilder builder = new X509v2CRLBuilder(subjectOf(issuer), period.thisUpdate());
        builder.setNextUpdate(period.nextUpdate());
        return builder;
    }

    /**
     * @param baseCrlNumber the number of the CRL that a delta CRL updates; {@code null} for a CRL that is no delta CRL
     */
    private static byte[] signedCrl(X509v2CRLBuilder builder, Ca issuer, BigInteger crlNumber,
            BigInteger baseCrlNumber) {
        try {
            builder.addExtension(Extension.cRLNumber, false, new CRLNumber(crlNumber));
            if (baseCrlNumber != null) {
                builder.addExtension(Extension.deltaCRLIndicator, true, new CRLNumber(baseCrlNumber));
            }
            return builder.build(signer(issuer.keyPair())).getEncoded();
        } catch (IOException e) {
            throw new IllegalStateException("The test CRL cannot be built", e);
        }
    }

    private static CrlPeriod currentForADay() {
        Instant now = Instant.now();
        return new CrlPeriod(Date.from(now.minus(CLOCK_LEEWAY)), Date.from(now.plus(CRL_VALIDITY)));
    }

    private static CrlPeriod expiredFor(Duration sinceNextUpdate) {
        Instant now = Instant.now();
        return new CrlPeriod(Date.from(now.minus(CRL_VALIDITY)), Date.from(now.minus(sinceNextUpdate)));
    }

    private static CrlPeriod expiredADayAgo() {
        Instant now = Instant.now();
        return new CrlPeriod(Date.from(now.minus(CRL_VALIDITY.multipliedBy(2))), Date.from(now.minus(CRL_VALIDITY)));
    }

    private static ContentSigner signer(KeyPair keyPair) {
        try {
            return new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(keyPair.getPrivate());
        } catch (OperatorCreationException e) {
            throw new IllegalStateException("The test signer cannot be created", e);
        }
    }

    private static Validity validNow() {
        Instant now = Instant.now();
        return new Validity(now.minus(CLOCK_LEEWAY), now.plus(VALIDITY));
    }

    private static Validity endedADayAgo() {
        Instant now = Instant.now();
        return new Validity(now.minus(VALIDITY), now.minus(Duration.ofDays(1)));
    }

    private record Validity(Instant notBefore, Instant notAfter) {
    }

    private record CrlPeriod(Date thisUpdate, Date nextUpdate) {
    }

    /** What a certificate is for: its key usage and extended key usages. */
    private enum Usage {

        CA(KeyUsage.keyCertSign | KeyUsage.cRLSign),
        CLIENT(KeyUsage.digitalSignature, KeyPurposeId.id_kp_clientAuth),
        RA(KeyUsage.digitalSignature, KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_cmcRA),
        SERVER(KeyUsage.digitalSignature, KeyPurposeId.id_kp_serverAuth),
        ANY(KeyUsage.digitalSignature),
        END_ENTITY_ISSUER(KeyUsage.keyCertSign | KeyUsage.digitalSignature);

        private final int keyUsageBits;
        private final KeyPurposeId[] purposes;

        Usage(int keyUsageBits, KeyPurposeId... purposes) {
            this.keyUsageBits = keyUsageBits;
            this.purposes = purposes;
        }

        KeyUsage keyUsage() {
            return new KeyUsage(keyUsageBits);
        }

        KeyPurposeId[] purposes() {
            return purposes.clone();
        }
    }
}

package com.otilm.core.container;

import com.otilm.api.model.client.inspection.InspectedEntryDto;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.key.normalization.KeyDescription;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.KeySizeUtil;
import com.otilm.core.util.PlatformX500NameStyle;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

/**
 * Describes an entry of an uploaded file as the inspection reports it, with its certificate's fields as the inventory
 * records them for an uploaded certificate.
 */
public final class InspectedEntryMapper {

    private InspectedEntryMapper() {
    }

    /**
     * The entry as the inspection reports it, without whether a token profile would take its key.
     *
     * @param entry an entry of an uploaded file
     * @return the entry's description
     */
    public static InspectedEntryDto map(ContainerEntry entry) {
        InspectedEntryDto inspected = new InspectedEntryDto();
        inspected.setEntryReference(entry.reference());
        inspected.setKind(entry.kind());
        switch (entry) {
            case CertificateEntry certificate -> {
                inspected.setAlias(certificate.alias());
                describeCertificate(inspected, certificate.certificate());
            }
            case KeyEntry key -> {
                inspected.setAlias(key.alias());
                describeKey(inspected, key);
            }
            case SigningRequestEntry request -> describeRequest(inspected, request.request());
        }
        return inspected;
    }

    /** A key by what the normalizer found it to be, and a key pair by its leaf, counting the leaf and its issuers. */
    private static void describeKey(InspectedEntryDto inspected, KeyEntry key) {
        KeyDescription description = key.description();
        inspected.setKeyAlgorithm(description.algorithm());
        inspected.setKeyLength(KeySizeUtil.knownLength(description.length()));
        if (key.leaf() != null) {
            describeCertificate(inspected, key.leaf());
            inspected.setChainLength(1 + key.issuers().size());
        }
    }

    private static void describeCertificate(InspectedEntryDto inspected, X509CertificateHolder certificate) {
        X500NameStyle style = new PlatformX500NameStyle(false);
        inspected.setSubjectDn(X500Name.getInstance(style, certificate.getSubject()).toString());
        inspected.setIssuerDn(X500Name.getInstance(style, certificate.getIssuer()).toString());
        inspected.setSerialNumber(certificate.getSerialNumber().toString(16));
        inspected.setNotBefore(utc(certificate.getNotBefore().toInstant()));
        inspected.setNotAfter(utc(certificate.getNotAfter().toInstant()));
        byte[] encoded;
        try {
            encoded = certificate.getEncoded();
            inspected.setFingerprint(CertificateUtil.getThumbprint(encoded));
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("The certificate cannot be fingerprinted.", e);
        }
        describeSubjectAlternativeNames(inspected, encoded);
    }

    /**
     * The names as {@code type:value}, grouped by type in the order of the types' names, read as the inventory reads
     * them from the certificate parsed as X.509.
     */
    private static void describeSubjectAlternativeNames(InspectedEntryDto inspected, byte[] encoded) {
        Map<String, List<String>> names;
        try {
            names = new TreeMap<>(CertificateUtil.getSAN(CertificateUtil.getX509Certificate(encoded)));
        } catch (CertificateException e) {
            // A file can hold a certificate that does not parse as X.509, such as one with an unreadable key usage;
            // its names are then not reported, and the rest of it still is.
            return;
        }
        inspected
                .setSubjectAlternativeNames(names
                        .entrySet()
                        .stream()
                        .flatMap(typed -> typed.getValue().stream().map(name -> typed.getKey() + ":" + name))
                        .toList());
    }

    /** A request by its subject and, where the platform names its key's algorithm, the key's algorithm and length. */
    private static void describeRequest(InspectedEntryDto inspected, PKCS10CertificationRequest request) {
        inspected.setSubjectDn(X500Name.getInstance(new PlatformX500NameStyle(false), request.getSubject()).toString());
        PublicKey publicKey;
        try {
            publicKey = new JcaPKCS10CertificationRequest(request).getPublicKey();
        } catch (GeneralSecurityException e) {
            // The request's key cannot be read, so the platform names no algorithm for it.
            return;
        }
        KeyAlgorithm algorithm = CertificateUtil.getKeyAlgorithmEnumFromProviderName(publicKey.getAlgorithm());
        if (algorithm != KeyAlgorithm.UNKNOWN) {
            inspected.setKeyAlgorithm(algorithm);
            inspected.setKeyLength(KeySizeUtil.knownLength(KeySizeUtil.getKeyLength(publicKey)));
        }
    }

    private static OffsetDateTime utc(Instant instant) {
        return instant.atOffset(ZoneOffset.UTC);
    }

}

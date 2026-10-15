package com.otilm.core.container;

import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.key.normalization.DerivationBudget;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.Certificate;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * A file of DER: a certificate, a PKCS#7 {@code SignedData} of certificates, a certificate request, or a PKCS#8 key
 * with or without protection. A keystore is left to its own format.
 */
@Component
@Order(40)
class DerFormat implements ContainerFormat {

    @Override
    public boolean recognizes(byte[] file) {
        return !KeystoreDetection.isKeystore(file);
    }

    /** DER has no integrity check, so the passphrase never verifies it. */
    @Override
    public Contents read(byte[] file, Passphrase passphrase, DerivationBudget budget) {
        return new Contents(items(file), false);
    }

    /** The certificate, the certificates of a PKCS#7, the certificate request or the key the file holds. */
    private static List<RawItem> items(byte[] file) {
        ContainerLimits.requireNestingWithin(file);
        ASN1Primitive structure = parsed(file);
        if (attempt(structure, Certificate::getInstance) != null) {
            return List.of(new RawItem.Certificate(file, null, null));
        }
        ContentInfo contentInfo = attempt(structure, ContentInfo::getInstance);
        if (contentInfo != null && CMSObjectIdentifiers.signedData.equals(contentInfo.getContentType())) {
            return certificates(contentInfo);
        }
        if (attempt(structure, CertificationRequest::getInstance) != null) {
            return List.of(new RawItem.SigningRequest(file));
        }
        PrivateKeyInfo privateKeyInfo = attempt(structure, PrivateKeyInfo::getInstance);
        if (privateKeyInfo != null) {
            Arrays.fill(privateKeyInfo.getPrivateKey().getOctets(), (byte) 0);
            return List.of(key(file));
        }
        if (attempt(structure, EncryptedPrivateKeyInfo::getInstance) != null) {
            return List.of(key(file));
        }
        throw ContainerRefusal.notSupportedFormat();
    }

    /**
     * The certificates of a PKCS#7 {@code SignedData}; anything else it carries is not an entry.
     *
     * @param der the DER of the structure's {@code ContentInfo}
     * @return the certificates, in the order the structure holds them
     */
    static List<RawItem> signedDataCertificates(byte[] der) {
        ContainerLimits.requireNestingWithin(der);
        ContentInfo contentInfo = attempt(parsed(der), ContentInfo::getInstance);
        if (contentInfo == null || !CMSObjectIdentifiers.signedData.equals(contentInfo.getContentType())) {
            throw ContainerRefusal.notSupportedFormat();
        }
        return certificates(contentInfo);
    }

    /** The key as a copy of the file, which the entry keeps once the caller has overwritten the file. */
    private static RawItem key(byte[] file) {
        return new RawItem.Key(file.clone(), null, null, false);
    }

    /** The X.509 certificates among the structure's certificates; attribute and other certificates are no entries. */
    private static List<RawItem> certificates(ContentInfo contentInfo) {
        SignedData signedData = attempt(contentInfo.getContent(), SignedData::getInstance);
        if (signedData == null) {
            throw ContainerRefusal.notSupportedFormat();
        }
        List<RawItem> certificates = new ArrayList<>();
        ASN1Set choices = signedData.getCertificates();
        if (choices != null) {
            for (ASN1Encodable choice : choices) {
                if (choice instanceof ASN1Sequence certificate) {
                    certificates.add(new RawItem.Certificate(encoded(certificate), null, null));
                }
            }
        }
        return certificates;
    }

    /**
     * The structure as the file encodes it.
     *
     * @param structure a structure read from the file
     * @return its encoding
     */
    static byte[] encoded(ASN1Primitive structure) {
        try {
            return structure.getEncoded();
        } catch (IOException e) {
            throw ContainerRefusal.notSupportedFormat();
        }
    }

    /**
     * The one structure the DER holds. Bytes Bouncy Castle cannot read make the file one of no supported format; it
     * signals that with a range of unchecked exceptions, each meaning the same here.
     */
    private static ASN1Primitive parsed(byte[] der) {
        ASN1Primitive structure;
        try {
            structure = ASN1Primitive.fromByteArray(der);
        } catch (IOException | RuntimeException e) {
            throw ContainerRefusal.notSupportedFormat();
        }
        if (structure == null) {
            throw ContainerRefusal.notSupportedFormat();
        }
        return structure;
    }

    /** The structure read as the given type, or {@code null} when it is not one. */
    private static <T> T attempt(ASN1Encodable structure, Function<Object, T> reader) {
        try {
            return reader.apply(structure);
        } catch (RuntimeException e) {
            return null;
        }
    }
}

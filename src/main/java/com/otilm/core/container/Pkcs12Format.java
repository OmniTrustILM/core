package com.otilm.core.container;

import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.container.Pkcs12Mac.Integrity;
import com.otilm.core.key.normalization.DerivationBudget;
import com.otilm.core.key.normalization.EmptyPassphrase;
import com.otilm.core.key.normalization.KeyFileRefusal;
import com.otilm.core.key.normalization.KeyNormalizer;
import com.otilm.core.key.normalization.KeyProtection;
import com.otilm.core.key.normalization.NestingDepth;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
import org.bouncycastle.asn1.pkcs.CertBag;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.pkcs.SecretBag;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.util.io.Streams;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * A PKCS#12 file, read with Bouncy Castle's PKCS#12 structures rather than the JCA key store: the keys, secret keys and
 * certificates its safes hold, with the names and key identifiers its bags carry.
 *
 * <p>
 * The file's MAC, when it has one, is verified with the passphrase before its content is read. An encrypted safe is
 * decrypted once its protection is accepted and charged; a safe protected for a recipient's key is refused. An empty
 * passphrase opens a file its writer protected with an empty password, whichever way the writer encoded it: as its
 * BMPString terminator alone, as OpenSSL and the JDK do, or as no bytes at all, as Bouncy Castle does. A safe under a
 * PKCS#12 scheme is decrypted with the encoding the MAC verified with.
 * </p>
 *
 * <p>
 * Once the MAC has verified, a safe or a key that the passphrase does not open is under another passphrase. A safe is
 * refused as such here; the file is read as verified, so that a key is refused as such once it is opened. Without a
 * MAC, such a failure reads as the unreadable refusal every protected key shares.
 * </p>
 */
@Component
@Order(10)
class Pkcs12Format implements ContainerFormat {

    /**
     * The protections a key may use but a safe may not: the JDK's key store protections, and the PBES1 schemes Bouncy
     * Castle's safe decryption does not implement.
     */
    private static final Set<ASN1ObjectIdentifier> KEY_ONLY_PROTECTIONS = Set
            .of(new ASN1ObjectIdentifier("1.3.6.1.4.1.42.2.17.1.1"), new ASN1ObjectIdentifier("1.3.6.1.4.1.42.2.19.1"),
                    PKCSObjectIdentifiers.pbeWithMD2AndDES_CBC, PKCSObjectIdentifiers.pbeWithMD5AndRC2_CBC,
                    PKCSObjectIdentifiers.pbeWithSHA1AndRC2_CBC);

    @Override
    public boolean recognizes(byte[] file) {
        return KeystoreDetection.isPkcs12(file);
    }

    @Override
    public Contents read(byte[] file, Passphrase passphrase, DerivationBudget budget) {
        char[] password = passphrase.characters();
        Bags bags = new Bags();
        try {
            Integrity integrity = readAuthenticatedSafe(structure(parsed(file), Pfx::getInstance), password, budget,
                    bags);
            return new Contents(bags.items(), integrity.verified());
        } catch (RuntimeException refusal) {
            RawItem.overwriteKeys(bags.items());
            throw refusal;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    /**
     * Verifies the file's MAC, then reads the bags of its safes; the content they are read from is overwritten once
     * read, since a safe may hold a key without protection.
     */
    private static Integrity readAuthenticatedSafe(Pfx pfx, char[] password, DerivationBudget budget, Bags bags) {
        byte[] authenticatedSafe = authenticatedSafe(pfx);
        try {
            Integrity integrity = Pkcs12Mac.verify(pfx.getMacData(), authenticatedSafe, password, budget);
            for (ContentInfo safe : structure(parsed(authenticatedSafe), AuthenticatedSafe::getInstance)
                    .getContentInfo()) {
                readSafe(safe, password, integrity, budget, bags);
            }
            return integrity;
        } finally {
            Arrays.fill(authenticatedSafe, (byte) 0);
        }
    }

    /**
     * The content the MAC covers, which holds the safes; a file whose integrity is protected with a signature, the
     * public-key integrity mode, is refused naming its content type.
     */
    private static byte[] authenticatedSafe(Pfx pfx) {
        ContentInfo authenticatedSafe = pfx.getAuthSafe();
        if (!PKCSObjectIdentifiers.data.equals(authenticatedSafe.getContentType())) {
            throw ContainerRefusal.integrityUnsupported(authenticatedSafe.getContentType().getId());
        }
        return structure(authenticatedSafe.getContent(), ASN1OctetString::getInstance).getOctets();
    }

    private static void readSafe(ContentInfo safe, char[] password, Integrity integrity, DerivationBudget budget,
            Bags bags) {
        ASN1ObjectIdentifier type = safe.getContentType();
        if (PKCSObjectIdentifiers.data.equals(type)) {
            byte[] content = structure(safe.getContent(), ASN1OctetString::getInstance).getOctets();
            try {
                readBags(structure(parsed(content), ASN1Sequence::getInstance), bags);
            } finally {
                Arrays.fill(content, (byte) 0);
            }
        } else if (PKCSObjectIdentifiers.encryptedData.equals(type)) {
            byte[] content = decrypted(structure(safe.getContent(), EncryptedData::getInstance), password, integrity,
                    budget);
            try {
                readBags(decryptedSafeContents(content, integrity), bags);
            } finally {
                Arrays.fill(content, (byte) 0);
            }
        } else if (PKCSObjectIdentifiers.envelopedData.equals(type)) {
            throw ContainerRefusal.recipientProtected();
        } else {
            throw ContainerRefusal.entryUnsupported(type.getId());
        }
    }

    /**
     * The content of an encrypted safe, decrypted with the passphrase once its protection is accepted and its key
     * derivation charged. A safe that does not open, or whose content nests deeper than a file may, reads the same.
     */
    private static byte[] decrypted(EncryptedData safe, char[] password, Integrity integrity, DerivationBudget budget) {
        AlgorithmIdentifier protection = structure(safe, EncryptedData::getEncryptionAlgorithm);
        byte[] encrypted = structure(safe, EncryptedData::getContent).getOctets();
        if (KEY_ONLY_PROTECTIONS.contains(protection.getAlgorithm())) {
            throw KeyFileRefusal.unsupportedProtection(protection.getAlgorithm().getId());
        }
        KeyProtection.requireAccepted(protection, budget);
        byte[] content;
        try {
            content = decrypt(protection, encrypted, password, integrity);
        } catch (IOException | GeneralSecurityException | OperatorCreationException | RuntimeException e) {
            throw integrity.notOpened();
        }
        if (!NestingDepth.within(content, KeyNormalizer.MAXIMUM_NESTING_DEPTH)) {
            Arrays.fill(content, (byte) 0);
            throw integrity.notOpened();
        }
        return content;
    }

    /**
     * Decrypts with Bouncy Castle's PKCS#12 decryption; under an empty passphrase, PBES2 is left to
     * {@link EmptyPassphrase}, and a PKCS#12 scheme takes the empty password as the MAC verified it.
     */
    private static byte[] decrypt(AlgorithmIdentifier protection, byte[] encrypted, char[] password,
            Integrity integrity) throws IOException, GeneralSecurityException, OperatorCreationException {
        if (password.length == 0 && EmptyPassphrase.decrypts(protection)) {
            return EmptyPassphrase.decrypt(protection, encrypted);
        }
        InputDecryptor decryptor = new JcePKCSPBEInputDecryptorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .setTryWrongPKCS12Zero(integrity == Integrity.TERMINATED_EMPTY_PASSWORD)
                .build(password)
                .get(protection);
        try (InputStream decrypted = decryptor.getInputStream(new ByteArrayInputStream(encrypted))) {
            return Streams.readAll(decrypted);
        }
    }

    /** The bags of a decrypted safe; content that is no safe contents means the passphrase did not open the safe. */
    private static ASN1Sequence decryptedSafeContents(byte[] content, Integrity integrity) {
        ASN1Sequence safeContents;
        try {
            safeContents = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(content));
        } catch (IOException | RuntimeException e) {
            throw integrity.notOpened();
        }
        if (safeContents == null) {
            throw integrity.notOpened();
        }
        return safeContents;
    }

    private static void readBags(ASN1Sequence safeContents, Bags bags) {
        for (ASN1Encodable element : safeContents) {
            readBag(structure(element, SafeBag::getInstance), bags);
        }
    }

    /** A bag: a key, a certificate, a secret key or nested safe contents; a bag of any other type is refused. */
    private static void readBag(SafeBag bag, Bags bags) {
        ASN1ObjectIdentifier type = bag.getBagId();
        ASN1Encodable value = bag.getBagValue();
        if (PKCSObjectIdentifiers.safeContentsBag.equals(type)) {
            readBags(structure(value, ASN1Sequence::getInstance), bags);
            return;
        }
        String alias = friendlyName(bag.getBagAttributes());
        byte[] localKeyId = localKeyId(bag.getBagAttributes());
        if (PKCSObjectIdentifiers.keyBag.equals(type)) {
            bags
                    .add(new RawItem.Key(plainKey(structure(value, PrivateKeyInfo::getInstance)), alias, localKeyId,
                            false));
        } else if (PKCSObjectIdentifiers.pkcs8ShroudedKeyBag.equals(type)) {
            bags
                    .add(new RawItem.Key(der(structure(value, EncryptedPrivateKeyInfo::getInstance)), alias, localKeyId,
                            false));
        } else if (PKCSObjectIdentifiers.certBag.equals(type)) {
            bags.add(new RawItem.Certificate(certificate(structure(value, CertBag::getInstance)), alias, localKeyId));
        } else if (PKCSObjectIdentifiers.secretBag.equals(type)) {
            readSecret(structure(value, SecretBag::getInstance), alias, localKeyId, bags);
        } else {
            throw ContainerRefusal.entryUnsupported(type.getId());
        }
    }

    /** The certificate of a bag holding an X.509 certificate; a certificate of any other type is refused. */
    private static byte[] certificate(CertBag bag) {
        if (!PKCSObjectIdentifiers.x509Certificate.equals(bag.getCertId())) {
            throw ContainerRefusal.entryUnsupported(bag.getCertId().getId());
        }
        return structure(bag.getCertValue(), ASN1OctetString::getInstance).getOctets();
    }

    /**
     * A secret key in the PKCS#8 shape the JDK stores it in, protected or not; the normalizer refuses one without
     * protection when the key is described. A secret of any other shape is refused naming its type.
     */
    private static void readSecret(SecretBag bag, String alias, byte[] localKeyId, Bags bags) {
        String type = bag.getSecretTypeId().getId();
        if (!(bag.getSecretValue() instanceof ASN1OctetString value)) {
            throw ContainerRefusal.entryUnsupported(type);
        }
        byte[] content = value.getOctets();
        try {
            ContainerLimits.requireNestingWithin(content);
            PrivateKeyInfo plain = attempt(content, PrivateKeyInfo::getInstance);
            if (plain != null) {
                bags.add(new RawItem.Key(plainKey(plain), alias, localKeyId, true));
                return;
            }
            EncryptedPrivateKeyInfo shrouded = attempt(content, EncryptedPrivateKeyInfo::getInstance);
            if (shrouded == null) {
                throw ContainerRefusal.entryUnsupported(type);
            }
            bags.add(new RawItem.Key(der(shrouded), alias, localKeyId, true));
        } finally {
            Arrays.fill(content, (byte) 0);
        }
    }

    /** A key without protection, as a copy of its DER; the parsed structure's own copy of the key is overwritten. */
    private static byte[] plainKey(PrivateKeyInfo key) {
        try {
            return der(key);
        } finally {
            Arrays.fill(key.getPrivateKey().getOctets(), (byte) 0);
        }
    }

    /** The bag's friendly name, which is the alias; none when it has none or it is no text. */
    private static String friendlyName(ASN1Set attributes) {
        return firstValue(attributes, PKCSObjectIdentifiers.pkcs_9_at_friendlyName) instanceof ASN1String name
                && !name.getString().isEmpty() ? name.getString() : null;
    }

    /**
     * The bag's local key identifier, a hint for choosing a key's certificate; none when it has none or it is no octet
     * string.
     */
    private static byte[] localKeyId(ASN1Set attributes) {
        return firstValue(attributes, PKCSObjectIdentifiers.pkcs_9_at_localKeyId) instanceof ASN1OctetString identifier
                ? identifier.getOctets()
                : null;
    }

    /** The first value of the first attribute of the type, or {@code null} when the bag carries none. */
    private static ASN1Encodable firstValue(ASN1Set attributes, ASN1ObjectIdentifier type) {
        if (attributes == null) {
            return null;
        }
        for (ASN1Encodable element : attributes) {
            Attribute attribute = structure(element, Attribute::getInstance);
            if (type.equals(attribute.getAttrType())) {
                ASN1Set values = attribute.getAttrValues();
                return values.size() > 0 ? values.getObjectAt(0) : null;
            }
        }
        return null;
    }

    /** The one structure the DER holds, its nesting checked before anything parses it. */
    private static ASN1Primitive parsed(byte[] der) {
        ContainerLimits.requireNestingWithin(der);
        try {
            return ASN1Primitive.fromByteArray(der);
        } catch (IOException | RuntimeException e) {
            throw ContainerRefusal.notSupportedFormat();
        }
    }

    /**
     * The structure read from the source. What Bouncy Castle cannot read makes the file one of no supported format; it
     * signals that with a range of unchecked exceptions, each meaning the same here.
     */
    private static <S, T> T structure(S source, Function<S, T> reader) {
        T structure;
        try {
            structure = reader.apply(source);
        } catch (RuntimeException e) {
            throw ContainerRefusal.notSupportedFormat();
        }
        if (structure == null) {
            throw ContainerRefusal.notSupportedFormat();
        }
        return structure;
    }

    /** The DER read as the given type, or {@code null} when it is not one. */
    private static <T> T attempt(byte[] der, Function<Object, T> reader) {
        try {
            return reader.apply(ASN1Primitive.fromByteArray(der));
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    private static byte[] der(ASN1Object structure) {
        try {
            return structure.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw ContainerRefusal.notSupportedFormat();
        }
    }

    /** What the safes hold, in file order, within the limits. */
    private static final class Bags {

        private final List<RawItem> items = new ArrayList<>();

        private int certificates;

        List<RawItem> items() {
            return items;
        }

        void add(RawItem.Certificate certificate) {
            items.add(certificate);
            certificates++;
            ContainerLimits.requireCertificatesWithin(certificates);
        }

        /** Adds a key; one over the limit is added first, so that the refusal overwrites it with the others. */
        void add(RawItem.Key key) {
            items.add(key);
            ContainerLimits.requireOtherEntriesWithin(items.size() - certificates);
        }
    }
}

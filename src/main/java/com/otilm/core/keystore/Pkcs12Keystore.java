package com.otilm.core.keystore;

import com.otilm.api.model.core.secret.Passphrase;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.util.PBKDF2Config;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;

/**
 * A PKCS#12 keystore around a key its connector exported. The key is never opened: its EncryptedPrivateKeyInfo becomes
 * the shrouded key bag as it is. The certificates are protected, and the file is authenticated, at the key's own
 * iteration count, with AES-256-CBC under PBKDF2-HMAC-SHA256 and a HMAC-SHA256 MAC, as OpenSSL 3 and the JDK write
 * PKCS#12 files by default.
 */
public final class Pkcs12Keystore {

    private static final int SALT_BYTES = 16;

    private Pkcs12Keystore() {
    }

    /**
     * The keystore of the entry, protected under the passphrase its key is protected under.
     *
     * @param entry the key and its certificates
     * @param passphrase the passphrase the key is protected under
     * @return the DER-encoded PKCS#12 file
     */
    public static byte[] assemble(KeystoreEntry entry, Passphrase passphrase) {
        char[] password = passphrase.characters();
        try {
            EncryptedPrivateKeyInfo key = EncryptedPrivateKeyInfo.getInstance(entry.encryptedPrivateKeyInfo());
            int iterations = iterationsOf(key);
            byte[] localKeyId = sha256(entry.leaf());
            PKCS12PfxPduBuilder pfx = new PKCS12PfxPduBuilder();
            pfx.addEncryptedData(certificateEncryptor(iterations, password), certificateBags(entry, localKeyId));
            pfx.addData(keyBag(key, entry.keyName(), localKeyId));
            return pfx
                    .build(new JcePKCS12MacCalculatorBuilder(NISTObjectIdentifiers.id_sha256)
                            .setIterationCount(iterations)
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME), password)
                    .getEncoded(ASN1Encoding.DER);
        } catch (IOException | OperatorCreationException | PKCSException | IllegalArgumentException e) {
            throw new IllegalStateException("The keystore could not be assembled.", e);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    /** The key's PBKDF2 iteration count; the export has already held the key to PBES2 with PBKDF2. */
    private static int iterationsOf(EncryptedPrivateKeyInfo key) {
        PBES2Parameters pbes2 = PBES2Parameters.getInstance(key.getEncryptionAlgorithm().getParameters());
        return PBKDF2Params
                .getInstance(pbes2.getKeyDerivationFunc().getParameters())
                .getIterationCount()
                .intValueExact();
    }

    private static OutputEncryptor certificateEncryptor(int iterations, char[] password)
            throws OperatorCreationException {
        PBKDF2Config pbkdf2 = new PBKDF2Config.Builder()
                .withIterationCount(iterations)
                .withPRF(PBKDF2Config.PRF_SHA256)
                .withSaltLength(SALT_BYTES)
                .build();
        return new JcePKCSPBEOutputEncryptorBuilder(pbkdf2, NISTObjectIdentifiers.id_aes256_CBC)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(password);
    }

    private static PKCS12SafeBag keyBag(EncryptedPrivateKeyInfo key, String keyName, byte[] localKeyId) {
        DERSet attributes = new DERSet(new Attribute[]{
                new Attribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERSet(new DERBMPString(keyName))),
                new Attribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, new DERSet(new DEROctetString(localKeyId)))});
        return new PKCS12SafeBag(new SafeBag(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag, key, attributes));
    }

    private static PKCS12SafeBag[] certificateBags(KeystoreEntry entry, byte[] localKeyId) throws IOException {
        List<PKCS12SafeBag> bags = new ArrayList<>();
        bags
                .add(new PKCS12SafeBagBuilder(new X509CertificateHolder(entry.leaf()))
                        .addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                                new DERBMPString(entry.keyName()))
                        .addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, new DEROctetString(localKeyId))
                        .build());
        Set<String> used = new HashSet<>();
        used.add(entry.keyName().toLowerCase(Locale.ROOT));
        for (byte[] issuer : entry.issuers()) {
            X509CertificateHolder holder = new X509CertificateHolder(issuer);
            bags
                    .add(new PKCS12SafeBagBuilder(holder)
                            .addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                                    new DERBMPString(uniqueName(nameOf(holder), used)))
                            .build());
        }
        return bags.toArray(PKCS12SafeBag[]::new);
    }

    /** The issuer's subject common name, or its subject when it has none. */
    private static String nameOf(X509CertificateHolder holder) {
        RDN[] commonNames = holder.getSubject().getRDNs(BCStyle.CN);
        if (commonNames.length == 0) {
            return holder.getSubject().toString();
        }
        for (AttributeTypeAndValue attribute : commonNames[0].getTypesAndValues()) {
            if (attribute.getType().equals(BCStyle.CN)) {
                return attribute.getValue().toString();
            }
        }
        return holder.getSubject().toString();
    }

    /**
     * The name, or the first of "name (2)", "name (3)" and so on that is still unused. Case does not count: the JDK
     * lowercases the aliases it reads.
     */
    private static String uniqueName(String name, Set<String> used) {
        String candidate = name;
        int suffix = 1;
        while (!used.add(candidate.toLowerCase(Locale.ROOT))) {
            suffix++;
            candidate = name + " (" + suffix + ")";
        }
        return candidate;
    }

    private static byte[] sha256(byte[] content) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(content);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available.", e);
        }
    }
}

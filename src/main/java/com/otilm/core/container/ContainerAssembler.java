package com.otilm.core.container;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.container.ContainerFormat.Contents;
import com.otilm.core.key.normalization.DerivationBudget;
import com.otilm.core.key.normalization.ExplicitCurve;
import com.otilm.core.key.normalization.KeyDescription;
import com.otilm.core.key.normalization.KeyFileRefusal;
import com.otilm.core.key.normalization.KeyNormalizer;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Component;

/**
 * Turns what a format found into the file's entries. Every key is described once by the key normalizer and bound to the
 * certificate that carries its public key, together with that certificate's issuers the file holds; a certificate in no
 * key's chain is an entry of its own.
 *
 * <p>
 * A chain follows the issuer names and key identifiers the certificates carry. No signature is verified, so the work
 * stays small whatever keys the certificates hold.
 * </p>
 *
 * <p>
 * The entries keep file order, a key where the file holds it. Items of the same reference are one entry, where the
 * first of them stands, named by the first alias any of them has.
 * </p>
 */
@Component
class ContainerAssembler {

    private final KeyNormalizer normalizer;

    ContainerAssembler(KeyNormalizer normalizer) {
        this.normalizer = normalizer;
    }

    /**
     * The file's entries. The limits are checked before anything is read, and every certificate and request is read
     * before any key is opened. A key that no entry keeps is overwritten, and every key when the file is refused.
     *
     * @param contents what the format found, in file order, and whether the passphrase verified the file
     * @param passphrase the passphrase the file was read with, which opens its keys
     * @param budget the budget of the file, charged every key's derivation
     * @return the entries, in file order
     */
    List<ContainerEntry> assemble(Contents contents, Passphrase passphrase, DerivationBudget budget) {
        List<RawItem> items = contents.items();
        List<ContainerEntry> entries = List.of();
        try {
            requireWithinLimits(items);
            Map<String, Read> unique = new LinkedHashMap<>();
            Map<String, String> aliases = new HashMap<>();
            for (Read read : read(contents, passphrase, budget)) {
                unique.putIfAbsent(read.reference(), read);
                if (read.alias() != null) {
                    aliases.putIfAbsent(read.reference(), read.alias());
                }
            }
            entries = entries(unique.values(), aliases);
            return entries;
        } finally {
            overwriteKeysNotKept(items, entries);
        }
    }

    private static void requireWithinLimits(List<RawItem> items) {
        int certificates = (int) items.stream().filter(RawItem.Certificate.class::isInstance).count();
        ContainerLimits.requireCertificatesWithin(certificates);
        ContainerLimits.requireOtherEntriesWithin(items.size() - certificates);
    }

    /**
     * Refuses a certificate or request whose public key states a curve larger than any the platform holds by name, as a
     * file of no supported format, before anything builds a key from it: Bouncy Castle would check the key's generator
     * against the order the file states, at a cost that grows with that order and that nothing charges.
     */
    private static void requireNamedCurveSize(SubjectPublicKeyInfo publicKey) {
        if (ExplicitCurve.largerThanAnyNamed(publicKey.getAlgorithm())) {
            throw ContainerRefusal.notSupportedFormat();
        }
    }

    /** Every item read, in file order; the keys are opened last, so that a damaged certificate costs no derivation. */
    private List<Read> read(Contents contents, Passphrase passphrase, DerivationBudget budget) {
        List<RawItem> items = contents.items();
        Read[] read = new Read[items.size()];
        for (int index = 0; index < read.length; index++) {
            if (items.get(index) instanceof RawItem.Certificate certificate) {
                read[index] = Certified.of(certificate);
            } else if (items.get(index) instanceof RawItem.SigningRequest request) {
                read[index] = Requested.of(request);
            }
        }
        for (int index = 0; index < read.length; index++) {
            if (items.get(index) instanceof RawItem.Key key) {
                read[index] = described(key, passphrase, contents.verified(), budget);
            }
        }
        return Arrays.asList(read);
    }

    private Described described(RawItem.Key key, Passphrase passphrase, boolean verified, DerivationBudget budget) {
        KeyDescription description = description(key.keyFile(), passphrase, verified, budget);
        byte[] publicKey = description.subjectPublicKeyInfo();
        String reference = publicKey != null ? EntryReference.of(publicKey) : heldReference(key.keyFile());
        return new Described(reference, key, description);
    }

    /**
     * What the normalizer finds the key to be. In a file whose integrity the passphrase verified, a key the passphrase
     * does not open is under a passphrase of its own, which refuses the file; any other refusal stands as it is.
     */
    private KeyDescription description(byte[] keyFile, Passphrase passphrase, boolean verified,
            DerivationBudget budget) {
        try {
            return normalizer.describe(keyFile, passphrase, budget);
        } catch (ValidationException refusal) {
            throw verified && KeyFileRefusal.UNREADABLE.equals(refusal.getMessage())
                    ? ContainerRefusal.twoPassphrases()
                    : refusal;
        }
    }

    /**
     * The reference of a key without a public key to take: the SHA-256 of the key as the file holds it, the content of
     * its block for a PEM key.
     */
    private static String heldReference(byte[] keyFile) {
        if (!PemFormat.armored(keyFile)) {
            return EntryReference.of(keyFile);
        }
        byte[] content = PemFormat.blockContent(keyFile);
        try {
            return EntryReference.of(content);
        } finally {
            Arrays.fill(content, (byte) 0);
        }
    }

    /**
     * The entries of the items, each item the first of its reference and named by the reference's alias. Every key is
     * bound to its chain, and a certificate in a key's chain is part of that key's entry rather than one of its own.
     */
    private static List<ContainerEntry> entries(Collection<Read> unique, Map<String, String> aliases) {
        List<Certified> certificates = unique
                .stream()
                .filter(Certified.class::isInstance)
                .map(Certified.class::cast)
                .toList();
        Issuers issuers = new Issuers(certificates);
        Map<Described, List<Certified>> chains = new IdentityHashMap<>();
        Set<Certified> chained = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Read read : unique) {
            if (read instanceof Described key) {
                List<Certified> chain = leafOf(key, certificates).map(issuers::chainFrom).orElse(List.of());
                chains.put(key, chain);
                chained.addAll(chain);
            }
        }
        return unique.stream().filter(read -> !chained.contains(read)).<ContainerEntry>map(read -> switch (read) {
            case Certified certificate -> certificate.entry(aliases.get(certificate.reference()));
            case Described key -> key.entry(chains.get(key), aliases.get(key.reference()));
            case Requested request -> request.entry();
        }).toList();
    }

    /**
     * The certificate carrying the key's public key, compared as DER: of several, the one the file gives the key's
     * identifier, otherwise the one valid from the latest time. The identifier only chooses; it never binds. A key
     * without a public key, such as a secret key, has no certificate.
     */
    private static Optional<Certified> leafOf(Described key, List<Certified> certificates) {
        byte[] publicKey = key.description().subjectPublicKeyInfo();
        if (publicKey == null) {
            return Optional.empty();
        }
        Certified leaf = null;
        for (Certified candidate : certificates) {
            if (Arrays.equals(candidate.subjectPublicKeyInfo(), publicKey)) {
                if (identifies(key, candidate)) {
                    return Optional.of(candidate);
                }
                if (leaf == null || candidate.notBefore().isAfter(leaf.notBefore())) {
                    leaf = candidate;
                }
            }
        }
        return Optional.ofNullable(leaf);
    }

    private static boolean identifies(Described key, Certified candidate) {
        byte[] localKeyId = key.item().localKeyId();
        return localKeyId != null && Arrays.equals(localKeyId, candidate.item().localKeyId());
    }

    /**
     * What one item of the file was read as: a certificate, a key the normalizer described, or a certificate request.
     * Every item is read, copies included; of the items sharing a reference, the first stands for them all.
     */
    private sealed interface Read permits Certified, Described, Requested {

        String reference();

        /** The name the file gives the item, or {@code null}. */
        String alias();
    }

    /**
     * A certificate of the file.
     *
     * @param subjectPublicKeyInfo the DER of the certificate's public key, which a key is bound by
     * @param link what links the certificate to its issuer
     */
    // S6218: compared by identity only, nothing hashes or prints it; the arrays are compared by content where needed.
    @SuppressWarnings("java:S6218")
    private record Certified(String reference, RawItem.Certificate item, X509CertificateHolder holder,
            byte[] subjectPublicKeyInfo, Instant notBefore, Link link) implements Read {

        /**
         * The certificate the DER holds. DER that is no certificate makes the file one of no supported format; Bouncy
         * Castle signals it with a range of unchecked exceptions, each meaning the same here. So does a certificate
         * whose public key states a curve larger than any the platform holds by name.
         */
        static Certified of(RawItem.Certificate certificate) {
            ContainerLimits.requireNestingWithin(certificate.der());
            try {
                X509CertificateHolder holder = new X509CertificateHolder(certificate.der());
                requireNamedCurveSize(holder.getSubjectPublicKeyInfo());
                return new Certified(EntryReference.of(holder.getEncoded()), certificate, holder,
                        holder.getSubjectPublicKeyInfo().getEncoded(ASN1Encoding.DER),
                        holder.getNotBefore().toInstant(), Link.of(holder));
            } catch (IOException | RuntimeException e) {
                throw ContainerRefusal.notSupportedFormat();
            }
        }

        @Override
        public String alias() {
            return item.alias();
        }

        CertificateEntry entry(String alias) {
            return new CertificateEntry(reference, alias, holder);
        }
    }

    /**
     * What links a certificate to its issuer: its names, compared by their DER encoding, and its key identifiers, each
     * empty when the certificate carries none.
     */
    // S6218: nothing compares, hashes or prints a link as a whole; its arrays are compared by content.
    @SuppressWarnings("java:S6218")
    private record Link(byte[] subject, byte[] issuer, Optional<byte[]> subjectKeyIdentifier,
            Optional<byte[]> authorityKeyIdentifier) {

        static Link of(X509CertificateHolder holder) throws IOException {
            return new Link(holder.getSubject().getEncoded(ASN1Encoding.DER),
                    holder.getIssuer().getEncoded(ASN1Encoding.DER),
                    keyIdentifier(holder, Extension.subjectKeyIdentifier,
                            value -> SubjectKeyIdentifier.getInstance(value).getKeyIdentifier()),
                    keyIdentifier(holder, Extension.authorityKeyIdentifier,
                            value -> AuthorityKeyIdentifier.getInstance(value).getKeyIdentifierOctets()));
        }

        /** Whether the certificate names itself as its issuer, which ends a chain. */
        boolean selfIssued() {
            return Arrays.equals(subject, issuer);
        }

        /**
         * Whether the candidate is the issuer this certificate names: the candidate's subject is this certificate's
         * issuer and, when both carry them, the candidate's subject key identifier is this certificate's authority key
         * identifier. An empty identifier identifies no key, so it matches none.
         */
        boolean namesAsIssuer(Link candidate) {
            return Arrays.equals(candidate.subject, issuer) && authorityKeyIdentifier
                    .flatMap(authority -> candidate.subjectKeyIdentifier
                            .map(candidateKey -> authority.length > 0 && Arrays.equals(candidateKey, authority)))
                    .orElse(true);
        }

        /**
         * The key identifier an extension states, or none when the certificate carries none. An identifier that cannot
         * be read is left out, as though the certificate carried none.
         */
        private static Optional<byte[]> keyIdentifier(X509CertificateHolder holder, ASN1ObjectIdentifier extension,
                Function<ASN1Encodable, byte[]> identifier) {
            Extension value = holder.getExtension(extension);
            if (value == null) {
                return Optional.empty();
            }
            try {
                return Optional.ofNullable(identifier.apply(value.getParsedValue()));
            } catch (RuntimeException e) {
                return Optional.empty();
            }
        }
    }

    /** A key the normalizer described. */
    private record Described(String reference, RawItem.Key item, KeyDescription description) implements Read {

        @Override
        public String alias() {
            return item.alias();
        }

        /** The key's entry, with its chain: the leaf first, then its issuers, nearest first; none when unbound. */
        KeyEntry entry(List<Certified> chain, String alias) {
            X509CertificateHolder leaf = chain.isEmpty() ? null : chain.getFirst().holder();
            List<X509CertificateHolder> issuers = chain.stream().skip(1).map(Certified::holder).toList();
            return new KeyEntry(reference, alias, item.keyFile(), description, leaf, issuers, secret());
        }

        /**
         * Whether the key is a secret key: as the normalizer found it, or as the file stores it when the platform does
         * not support the key's algorithm.
         */
        private boolean secret() {
            return description.type() != null ? description.type() == KeyRequestType.SECRET : item.secret();
        }
    }

    /** A certificate request of the file. */
    private record Requested(String reference, PKCS10CertificationRequest request) implements Read {

        static Requested of(RawItem.SigningRequest request) {
            ContainerLimits.requireNestingWithin(request.der());
            try {
                PKCS10CertificationRequest parsed = new PKCS10CertificationRequest(request.der());
                requireNamedCurveSize(parsed.getSubjectPublicKeyInfo());
                return new Requested(EntryReference.of(parsed.getEncoded()), parsed);
            } catch (IOException | RuntimeException e) {
                throw ContainerRefusal.notSupportedFormat();
            }
        }

        @Override
        public String alias() {
            return null;
        }

        SigningRequestEntry entry() {
            return new SigningRequestEntry(reference, request);
        }
    }

    /** The issuer of each certificate of the file, worked out once however many chains the certificate is in. */
    private static final class Issuers {

        private final List<Certified> certificates;

        private final Map<Certified, Optional<Certified>> known = new IdentityHashMap<>();

        Issuers(List<Certified> certificates) {
            this.certificates = certificates;
        }

        /**
         * The chain from the leaf: the leaf, then the issuer of each certificate in turn, until a self-issued
         * certificate, one whose issuer the file does not hold, or a certificate already in the chain.
         */
        List<Certified> chainFrom(Certified leaf) {
            List<Certified> chain = new ArrayList<>();
            Set<Certified> seen = Collections.newSetFromMap(new IdentityHashMap<>());
            Optional<Certified> next = Optional.of(leaf);
            while (next.isPresent() && seen.add(next.get())) {
                chain.add(next.get());
                next = issuerOf(next.get());
            }
            return chain;
        }

        private Optional<Certified> issuerOf(Certified certificate) {
            return known.computeIfAbsent(certificate, this::findIssuer);
        }

        /** The first certificate of the file that is the issuer this one names; none for a self-issued certificate. */
        private Optional<Certified> findIssuer(Certified certificate) {
            Link link = certificate.link();
            if (link.selfIssued()) {
                return Optional.empty();
            }
            return certificates.stream().filter(candidate -> link.namesAsIssuer(candidate.link())).findFirst();
        }
    }

    /** Overwrites every key the format found that no entry keeps: a later copy of a key, or all when refused. */
    private static void overwriteKeysNotKept(List<RawItem> items, List<ContainerEntry> entries) {
        Set<byte[]> kept = Collections.newSetFromMap(new IdentityHashMap<>());
        for (ContainerEntry entry : entries) {
            if (entry instanceof KeyEntry key) {
                kept.add(key.keyFile());
            }
        }
        for (RawItem item : items) {
            if (item instanceof RawItem.Key key && !kept.contains(key.keyFile())) {
                Arrays.fill(key.keyFile(), (byte) 0);
            }
        }
    }
}

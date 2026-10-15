package com.otilm.core.container;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.inspection.InspectedEntryKind;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.container.ContainerFixtures.Chain;
import com.otilm.core.container.ContainerFormat.Contents;
import com.otilm.core.key.normalization.DerivationBudget;
import com.otilm.core.key.normalization.KeyFileRefusal;
import com.otilm.core.key.normalization.KeyNormalizer;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static com.otilm.core.container.ContainerFixtures.sha256;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ContainerAssemblerTest {

    private static final ContainerAssembler ASSEMBLER = new ContainerAssembler(new KeyNormalizer());

    /** The passphrase the reader reads a file with when it is given none. */
    private static final Passphrase EMPTY_PASSPHRASE = new Passphrase(new char[0]);

    private static final char[] OTHER_PASSPHRASE = "another passphrase".toCharArray();

    private static final byte[] HINT = {0x01, 0x02, 0x03, 0x04};

    private static final byte[] OTHER_HINT = {0x05, 0x06, 0x07, 0x08};

    private static final byte[] OTHER_KEY_ID = {0x0A, 0x0A};

    private static final byte[] KEY_ID = {0x0B, 0x0B};

    private static Chain chain;

    @BeforeAll
    static void fixtures() throws Exception {
        ContainerFixtures.registerProviders();
        chain = ContainerFixtures.rsaChain();
    }

    @Test
    void assemble_putsACertificateSharedByTwoChainsInBoth() throws Exception {
        // given
        KeyPair otherKey = ContainerFixtures.rsa();
        X509CertificateHolder otherLeaf = ContainerFixtures
                .certificate("CN=Other leaf", otherKey.getPublic(), "CN=Intermediate",
                        chain.intermediateKey().getPrivate(), ContainerFixtures.daysAgo(1));
        List<RawItem> items = List
                .of(certificate(chain.root()), certificate(chain.intermediate()), certificate(chain.leaf()),
                        certificate(otherLeaf), key(chain.leafKey(), null), key(otherKey, null));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        List<ContainerEntry> entries = assemble(items, budget);

        // then
        assertThat(entries)
                .hasSize(2)
                .allSatisfy(entry -> assertThat(entry)
                        .isInstanceOfSatisfying(KeyEntry.class,
                                key -> assertThat(key.issuers()).containsExactly(chain.intermediate(), chain.root())));
        assertThat(entries).map(entry -> ((KeyEntry) entry).leaf()).containsExactly(chain.leaf(), otherLeaf);
    }

    @Test
    void assemble_collapsesTwoCopiesOfOneCertificate() throws Exception {
        // given
        byte[] der = chain.leaf().getEncoded();
        List<RawItem> items = List
                .of(new RawItem.Certificate(der, "first", null), new RawItem.Certificate(der.clone(), "second", null));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        List<ContainerEntry> entries = assemble(items, budget);

        // then
        assertThat(entries).singleElement().isInstanceOfSatisfying(CertificateEntry.class, entry -> {
            assertThat(entry.reference()).isEqualTo(sha256(der));
            assertThat(entry.alias()).isEqualTo("first");
        });
    }

    @Test
    void assemble_collapsesTwoCopiesOfOneKeyAndOverwritesTheSecond() {
        // given
        byte[] first = ContainerFixtures.pkcs8(chain.leafKey());
        byte[] second = first.clone();
        List<RawItem> items = List
                .of(new RawItem.Key(first, "first", null, false), new RawItem.Key(second, "second", null, false));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        List<ContainerEntry> entries = assemble(items, budget);

        // then
        assertThat(entries).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.alias()).isEqualTo("first");
            assertThat(entry.keyFile()).isSameAs(first).isEqualTo(ContainerFixtures.pkcs8(chain.leafKey()));
        });
        assertThat(second).containsOnly(0);
    }

    @Test
    void assemble_choosesTheLeafWhoseLocalKeyIdMatchesTheKeys() throws Exception {
        // given
        KeyPair keyPair = ContainerFixtures.rsa();
        X509CertificateHolder earlier = issued(keyPair, 2);
        X509CertificateHolder later = issued(keyPair, 1);
        List<RawItem> items = List
                .of(new RawItem.Certificate(earlier.getEncoded(), null, HINT),
                        new RawItem.Certificate(later.getEncoded(), null, OTHER_HINT), key(keyPair, HINT.clone()));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        List<ContainerEntry> entries = assemble(items, budget);

        // then
        assertThat(entries)
                .extracting(ContainerEntry::kind)
                .containsExactly(InspectedEntryKind.CERTIFICATE, InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
        assertThat(((CertificateEntry) entries.getFirst()).certificate()).isEqualTo(later);
        assertThat(((KeyEntry) entries.getLast()).leaf()).isEqualTo(earlier);
    }

    @Test
    void assemble_choosesTheLatestLeafWithoutALocalKeyId() throws Exception {
        // given
        KeyPair keyPair = ContainerFixtures.rsa();
        X509CertificateHolder earlier = issued(keyPair, 2);
        X509CertificateHolder later = issued(keyPair, 1);
        List<RawItem> items = List.of(certificate(earlier), certificate(later), key(keyPair, null));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        List<ContainerEntry> entries = assemble(items, budget);

        // then
        assertThat(entries)
                .extracting(ContainerEntry::kind)
                .containsExactly(InspectedEntryKind.CERTIFICATE, InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
        assertThat(((CertificateEntry) entries.getFirst()).certificate()).isEqualTo(earlier);
        assertThat(((KeyEntry) entries.getLast()).leaf()).isEqualTo(later);
    }

    @Test
    @Timeout(10)
    void assemble_endsAChainAtACertificateAlreadyInIt() throws Exception {
        // given
        KeyPair first = ContainerFixtures.rsa();
        KeyPair second = ContainerFixtures.rsa();
        X509CertificateHolder firstCa = ContainerFixtures
                .certificate("CN=First", first.getPublic(), "CN=Second", second.getPrivate(),
                        ContainerFixtures.daysAgo(1));
        X509CertificateHolder secondCa = ContainerFixtures
                .certificate("CN=Second", second.getPublic(), "CN=First", first.getPrivate(),
                        ContainerFixtures.daysAgo(1));
        X509CertificateHolder leaf = ContainerFixtures
                .certificate("CN=Leaf", chain.leafKey().getPublic(), "CN=First", first.getPrivate(),
                        ContainerFixtures.daysAgo(1));
        List<RawItem> items = List
                .of(certificate(leaf), certificate(firstCa), certificate(secondCa), key(chain.leafKey(), null));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        List<ContainerEntry> entries = assemble(items, budget);

        // then
        assertThat(entries).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.leaf()).isEqualTo(leaf);
            assertThat(entry.issuers()).containsExactly(firstCa, secondCa);
        });
    }

    @Test
    void assemble_endsAChainAtASelfIssuedCertificate() throws Exception {
        // given
        KeyPair oldRootKey = ContainerFixtures.ec();
        KeyPair newRootKey = ContainerFixtures.ec();
        KeyPair leafKey = ContainerFixtures.ec();
        X509CertificateHolder oldRoot = ContainerFixtures
                .withKeyIdentifiers("CN=Root", oldRootKey.getPublic(), "CN=Root", oldRootKey.getPrivate(), OTHER_KEY_ID,
                        null);
        X509CertificateHolder newRoot = ContainerFixtures
                .withKeyIdentifiers("CN=Root", newRootKey.getPublic(), "CN=Root", newRootKey.getPrivate(), KEY_ID,
                        null);
        X509CertificateHolder leaf = ContainerFixtures
                .withKeyIdentifiers("CN=Leaf", leafKey.getPublic(), "CN=Root", newRootKey.getPrivate(), null, KEY_ID);
        List<RawItem> items = List
                .of(certificate(oldRoot), certificate(newRoot), certificate(leaf), key(leafKey, null));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        List<ContainerEntry> entries = assemble(items, budget);

        // then
        assertThat(entries)
                .extracting(ContainerEntry::kind)
                .containsExactly(InspectedEntryKind.CERTIFICATE, InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
        assertThat(((CertificateEntry) entries.getFirst()).certificate()).isEqualTo(oldRoot);
        assertThat(((KeyEntry) entries.getLast()).issuers()).containsExactly(newRoot);
    }

    @Test
    void assemble_endsAChainAtAnIssuerTheFileDoesNotHold() throws Exception {
        // given
        List<RawItem> items = List.of(certificate(chain.root()), certificate(chain.leaf()), key(chain.leafKey(), null));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        List<ContainerEntry> entries = assemble(items, budget);

        // then
        assertThat(entries)
                .extracting(ContainerEntry::kind)
                .containsExactly(InspectedEntryKind.CERTIFICATE, InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
        assertThat(entries.getLast()).isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.leaf()).isEqualTo(chain.leaf());
            assertThat(entry.issuers()).isEmpty();
        });
    }

    @Test
    void assemble_takesNoIssuerOfTheNameWhoseKeyIdentifierIsAnother() throws Exception {
        // given
        KeyPair impostorKey = ContainerFixtures.ec();
        KeyPair caKey = ContainerFixtures.ec();
        KeyPair leafKey = ContainerFixtures.ec();
        X509CertificateHolder impostor = ContainerFixtures
                .withKeyIdentifiers("CN=CA", impostorKey.getPublic(), "CN=Root", impostorKey.getPrivate(), OTHER_KEY_ID,
                        null);
        X509CertificateHolder ca = ContainerFixtures
                .withKeyIdentifiers("CN=CA", caKey.getPublic(), "CN=Root", caKey.getPrivate(), KEY_ID, null);
        X509CertificateHolder leaf = ContainerFixtures
                .withKeyIdentifiers("CN=Leaf", leafKey.getPublic(), "CN=CA", caKey.getPrivate(), null, KEY_ID);
        List<RawItem> items = List.of(certificate(impostor), certificate(ca), certificate(leaf), key(leafKey, null));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        List<ContainerEntry> entries = assemble(items, budget);

        // then
        assertThat(entries)
                .extracting(ContainerEntry::kind)
                .containsExactly(InspectedEntryKind.CERTIFICATE, InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
        assertThat(((CertificateEntry) entries.getFirst()).certificate()).isEqualTo(impostor);
        assertThat(((KeyEntry) entries.getLast()).issuers()).containsExactly(ca);
    }

    @Test
    void assemble_takesNoIssuerByEmptyKeyIdentifiers() throws Exception {
        // given
        KeyPair caKey = ContainerFixtures.ec();
        KeyPair leafKey = ContainerFixtures.ec();
        X509CertificateHolder ca = ContainerFixtures
                .withKeyIdentifiers("CN=CA", caKey.getPublic(), "CN=Root", caKey.getPrivate(), new byte[0], null);
        X509CertificateHolder leaf = ContainerFixtures
                .withKeyIdentifiers("CN=Leaf", leafKey.getPublic(), "CN=CA", caKey.getPrivate(), null, new byte[0]);
        List<RawItem> items = List.of(certificate(leaf), certificate(ca), key(leafKey, null));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        List<ContainerEntry> entries = assemble(items, budget);

        // then
        assertThat(entries)
                .extracting(ContainerEntry::kind)
                .containsExactly(InspectedEntryKind.CERTIFICATE, InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
        assertThat(((CertificateEntry) entries.getFirst()).certificate()).isEqualTo(ca);
        assertThat(((KeyEntry) entries.getLast()).issuers()).isEmpty();
    }

    @Test
    void assemble_takesTheFirstIssuerOfTheNameWithoutKeyIdentifiersNorSignatures() throws Exception {
        // given
        KeyPair firstKey = ContainerFixtures.ec();
        KeyPair secondKey = ContainerFixtures.ec();
        KeyPair leafKey = ContainerFixtures.ec();
        X509CertificateHolder first = ContainerFixtures
                .certificate("CN=CA", firstKey.getPublic(), "CN=Root", firstKey.getPrivate(),
                        ContainerFixtures.daysAgo(1));
        X509CertificateHolder second = ContainerFixtures
                .certificate("CN=CA", secondKey.getPublic(), "CN=Root", secondKey.getPrivate(),
                        ContainerFixtures.daysAgo(1));
        // signed with the second's key, which nothing checks
        X509CertificateHolder leaf = ContainerFixtures
                .certificate("CN=Leaf", leafKey.getPublic(), "CN=CA", secondKey.getPrivate(),
                        ContainerFixtures.daysAgo(1));
        List<RawItem> items = List.of(certificate(first), certificate(second), certificate(leaf), key(leafKey, null));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        List<ContainerEntry> entries = assemble(items, budget);

        // then
        assertThat(entries)
                .extracting(ContainerEntry::kind)
                .containsExactly(InspectedEntryKind.CERTIFICATE, InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
        assertThat(((CertificateEntry) entries.getFirst()).certificate()).isEqualTo(second);
        assertThat(((KeyEntry) entries.getLast()).issuers()).containsExactly(first);
    }

    @Test
    void assemble_takesAnIssuerWhoseKeyIdentifierCannotBeReadByItsName() throws Exception {
        // given
        KeyPair caKey = ContainerFixtures.ec();
        KeyPair leafKey = ContainerFixtures.ec();
        X509CertificateHolder ca = ContainerFixtures
                .withSubjectKeyIdentifierValue("CN=CA", caKey.getPublic(), "CN=Root", caKey.getPrivate(),
                        DERNull.INSTANCE.getEncoded());
        X509CertificateHolder leaf = ContainerFixtures
                .withKeyIdentifiers("CN=Leaf", leafKey.getPublic(), "CN=CA", caKey.getPrivate(), null, KEY_ID);
        List<RawItem> items = List.of(certificate(leaf), certificate(ca), key(leafKey, null));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        List<ContainerEntry> entries = assemble(items, budget);

        // then
        assertThat(entries)
                .singleElement()
                .isInstanceOfSatisfying(KeyEntry.class, entry -> assertThat(entry.issuers()).containsExactly(ca));
    }

    @Test
    void assemble_takesAnIssuerOfTheNameThatCarriesNoKeyIdentifier() throws Exception {
        // given
        KeyPair caKey = ContainerFixtures.ec();
        KeyPair leafKey = ContainerFixtures.ec();
        X509CertificateHolder ca = ContainerFixtures
                .certificate("CN=CA", caKey.getPublic(), "CN=Root", caKey.getPrivate(), ContainerFixtures.daysAgo(1));
        X509CertificateHolder leaf = ContainerFixtures
                .withKeyIdentifiers("CN=Leaf", leafKey.getPublic(), "CN=CA", caKey.getPrivate(), null, KEY_ID);
        List<RawItem> items = List.of(certificate(leaf), certificate(ca), key(leafKey, null));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        List<ContainerEntry> entries = assemble(items, budget);

        // then
        assertThat(entries)
                .singleElement()
                .isInstanceOfSatisfying(KeyEntry.class, entry -> assertThat(entry.issuers()).containsExactly(ca));
    }

    @Test
    void assemble_bindsNothingByAMisleadingLocalKeyId() throws Exception {
        // given
        List<RawItem> items = List
                .of(key(chain.leafKey(), HINT), new RawItem.Certificate(chain.intermediate().getEncoded(), null, HINT));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        List<ContainerEntry> entries = assemble(items, budget);

        // then
        assertThat(entries)
                .extracting(ContainerEntry::kind)
                .containsExactly(InspectedEntryKind.PRIVATE_KEY, InspectedEntryKind.CERTIFICATE);
        assertThat(((KeyEntry) entries.getFirst()).leaf()).isNull();
    }

    @Test
    void assemble_listsAnEd25519KeyByItsKeyFileNeverBound() throws Exception {
        // given
        KeyPair ed25519 = ContainerFixtures.ed25519();
        byte[] keyFile = ContainerFixtures.pkcs8(ed25519);
        List<RawItem> items = List
                .of(new RawItem.Key(keyFile, null, null, false),
                        certificate(ContainerFixtures.selfSigned(ed25519, "CN=Ed25519")));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        List<ContainerEntry> entries = assemble(items, budget);

        // then
        assertThat(entries)
                .extracting(ContainerEntry::kind)
                .containsExactly(InspectedEntryKind.PRIVATE_KEY, InspectedEntryKind.CERTIFICATE);
        assertThat(entries.getFirst()).isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.reference()).isEqualTo(sha256(ContainerFixtures.pkcs8(ed25519)));
            assertThat(entry.leaf()).isNull();
            assertThat(entry.description().unsupportedAlgorithm()).isEqualTo("1.3.101.112");
        });
    }

    @Test
    void assemble_refusesMoreCertificatesThanTheLimitBeforeReadingThem() {
        // given
        List<RawItem> items = IntStream
                .range(0, ContainerLimits.MAXIMUM_CERTIFICATES + 1)
                .<RawItem>mapToObj(index -> new RawItem.Certificate(new byte[]{0x01}, null, null))
                .toList();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> assemble(items, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.LIMIT_EXCEEDED.formatted("certificate count", 200));
    }

    @Test
    void assemble_refusesMoreKeysThanTheLimitBeforeOpeningThem() {
        // given
        List<RawItem> items = IntStream
                .range(0, ContainerLimits.MAXIMUM_OTHER_ENTRIES + 1)
                .<RawItem>mapToObj(index -> new RawItem.Key(new byte[]{0x01}, null, null, false))
                .toList();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> assemble(items, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.LIMIT_EXCEEDED.formatted("entry count", 100));
    }

    @Test
    void assemble_countsKeysAndSigningRequestsTogether() {
        // given
        int half = ContainerLimits.MAXIMUM_OTHER_ENTRIES / 2;
        List<RawItem> items = new ArrayList<>();
        for (int index = 0; index < half; index++) {
            items.add(new RawItem.Key(new byte[]{0x01}, null, null, false));
        }
        for (int index = 0; index <= half; index++) {
            items.add(new RawItem.SigningRequest(new byte[]{0x01}));
        }
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> assemble(items, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.LIMIT_EXCEEDED.formatted("entry count", 100));
    }

    @Test
    void assemble_acceptsTheMostCertificatesAFileMayHold() throws Exception {
        // given
        byte[] certificate = chain.root().getEncoded();
        List<RawItem> items = IntStream
                .range(0, ContainerLimits.MAXIMUM_CERTIFICATES)
                .<RawItem>mapToObj(index -> new RawItem.Certificate(certificate.clone(), null, null))
                .toList();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        List<ContainerEntry> entries = assemble(items, budget);

        // then
        assertThat(entries)
                .singleElement()
                .isInstanceOfSatisfying(CertificateEntry.class,
                        entry -> assertThat(entry.certificate()).isEqualTo(chain.root()));
    }

    @Test
    void assemble_acceptsTheMostKeysAndSigningRequestsAFileMayHold() throws Exception {
        // given
        byte[] key = ContainerFixtures.pkcs8(chain.leafKey());
        byte[] request = ContainerFixtures.signingRequest(chain.leafKey()).getEncoded();
        List<RawItem> items = new ArrayList<>();
        for (int index = 0; index < ContainerLimits.MAXIMUM_OTHER_ENTRIES / 2; index++) {
            items.add(new RawItem.Key(key.clone(), null, null, false));
            items.add(new RawItem.SigningRequest(request.clone()));
        }
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        List<ContainerEntry> entries = assemble(items, budget);

        // then
        assertThat(items).hasSize(ContainerLimits.MAXIMUM_OTHER_ENTRIES);
        assertThat(entries)
                .extracting(ContainerEntry::kind)
                .containsExactly(InspectedEntryKind.PRIVATE_KEY, InspectedEntryKind.SIGNING_REQUEST);
    }

    @Test
    void assemble_namesACollapsedEntryByTheFirstAliasOfItsCopies() throws Exception {
        // given
        byte[] certificate = chain.root().getEncoded();
        byte[] key = ContainerFixtures.pkcs8(chain.leafKey());
        List<RawItem> items = List
                .of(new RawItem.Certificate(certificate, null, null), new RawItem.Key(key, null, null, false),
                        new RawItem.Certificate(certificate.clone(), "root", null),
                        new RawItem.Key(key.clone(), "leaf", null, false),
                        new RawItem.Key(key.clone(), "later", null, false));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        List<ContainerEntry> entries = assemble(items, budget);

        // then
        assertThat(entries).hasSize(2);
        assertThat(entries.getFirst())
                .isInstanceOfSatisfying(CertificateEntry.class, entry -> assertThat(entry.alias()).isEqualTo("root"));
        assertThat(entries.getLast()).isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.alias()).isEqualTo("leaf");
            assertThat(entry.keyFile()).isSameAs(key);
        });
    }

    @Test
    void assemble_overwritesEveryKeyOfAFileItRefuses() {
        // given
        byte[] keyFile = ContainerFixtures.pkcs8(chain.leafKey());
        List<RawItem> items = new ArrayList<>();
        items.add(new RawItem.Key(keyFile, null, null, false));
        items.add(new RawItem.Certificate(new byte[]{0x30, 0x00}, null, null));
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> assemble(items, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.NOT_SUPPORTED_FORMAT);
        assertThat(keyFile).containsOnly(0);
    }

    @Test
    void assemble_refusesAKeyThePassphraseDoesNotOpenInAVerifiedFileAsUnderAnotherPassphrase() throws Exception {
        // given
        byte[] keyFile = ContainerFixtures.encryptedPkcs8(chain.leafKey());
        Contents contents = new Contents(List.of(new RawItem.Key(keyFile, null, null, false)), true);
        Passphrase passphrase = new Passphrase(OTHER_PASSPHRASE);
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> ASSEMBLER.assemble(contents, passphrase, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.TWO_PASSPHRASES);
        assertThat(keyFile).containsOnly(0);
    }

    @Test
    void assemble_refusesAKeyThePassphraseDoesNotOpenInAFileNotVerifiedAsUnreadable() throws Exception {
        // given
        byte[] keyFile = ContainerFixtures.encryptedPkcs8(chain.leafKey());
        Contents contents = new Contents(List.of(new RawItem.Key(keyFile, null, null, false)), false);
        Passphrase passphrase = new Passphrase(OTHER_PASSPHRASE);
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> ASSEMBLER.assemble(contents, passphrase, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    /** The entries of the items of a file that no passphrase verified, read without a passphrase. */
    private static List<ContainerEntry> assemble(List<RawItem> items, DerivationBudget budget) {
        return ASSEMBLER.assemble(new Contents(items, false), EMPTY_PASSPHRASE, budget);
    }

    /** A certificate for the key issued by the intermediate, valid from the given number of days ago. */
    private static X509CertificateHolder issued(KeyPair keyPair, int daysAgo) throws Exception {
        return ContainerFixtures
                .certificate("CN=Leaf", keyPair.getPublic(), "CN=Intermediate", chain.intermediateKey().getPrivate(),
                        ContainerFixtures.daysAgo(daysAgo));
    }

    private static RawItem certificate(X509CertificateHolder certificate) throws Exception {
        return new RawItem.Certificate(certificate.getEncoded(), null, null);
    }

    private static RawItem key(KeyPair keyPair, byte[] localKeyId) {
        return new RawItem.Key(ContainerFixtures.pkcs8(keyPair), null, localKeyId, false);
    }
}

package com.otilm.core.service.impl;

import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.events.handlers.discovery.DiscoveredCertificateImport;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.service.writer.DiscoveryCertificateContentWriter;
import com.otilm.core.util.CertificateUtil;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The losing side of an insert race, which no integration test can reach: grouping removes the race inside one
 * discovery, and two discoveries racing on the same certificate cannot be forced deterministically. Stubbing the
 * repository is what makes the branch reachable at all.
 *
 * <p>
 * What matters is which UUID the loser returns. Returning the one it generated locally instead of the winner's
 * committed row would leave the keys and metadata written afterwards pointing at a certificate that does not exist.
 */
class CertificateServiceImplDiscoveredImportTest {

    private final CertificateRepository certificateRepository = mock(CertificateRepository.class);
    private final CertificateContentRepository certificateContentRepository = mock(CertificateContentRepository.class);
    private final DiscoveryCertificateContentWriter contentWriter = mock(DiscoveryCertificateContentWriter.class);
    private final CertificateServiceImpl service = new CertificateServiceImpl();

    private static Map<String, OidRecord> savedRdnCache;

    private X509Certificate x509Certificate;

    /**
     * {@code PlatformX500NameStyle} dereferences the RDN cache in a static initialiser, so it has to be primed before
     * the subject-name handling this method reaches touches that class.
     */
    @BeforeAll
    static void seedRdnCache() {
        Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE);
        savedRdnCache = existing == null ? null : new HashMap<>(existing);

        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
        OidHandler
                .cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
                        OidRecord.builder().displayName("Common Name").code("CN").build());
    }

    @AfterAll
    static void restoreRdnCache() {
        OidHandler
                .cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE,
                        savedRdnCache != null ? savedRdnCache : new HashMap<>());
    }

    @BeforeEach
    void setUp() throws Exception {
        service.setCertificateRepository(certificateRepository);
        service.setCertificateContentRepository(certificateContentRepository);
        service.setDiscoveryCertificateContentWriter(contentWriter);
        service.setAuditorAware(() -> Optional.of("discovery-operator"));

        x509Certificate = CertificateGeneratorHelper.generateCACertificate(null, "CN=discovered");

        CertificateContent content = new CertificateContent();
        content.setId(11L);
        content.setFingerprint(CertificateUtil.getThumbprint(x509Certificate));
        when(certificateContentRepository.findByFingerprint(anyString())).thenReturn(content);
    }

    @Test
    void adoptsTheCommittedRowWhenTheInsertLostTheRace() throws Exception {
        Certificate winner = new Certificate();
        winner.setUuid(UUID.randomUUID());
        // Absent when the method first looks, present by the time it re-reads: what the losing side observes, and
        // the only ordering under which the conflict-resolving insert reports nothing inserted.
        when(certificateRepository.findByFingerprint(anyString()))
                .thenReturn(Optional.empty())
                .thenReturn(Optional.of(winner));

        DiscoveredCertificateImport result = service.createDiscoveredCertificateAtomic(x509Certificate);

        assertThat(result.certificate().getUuid())
                .as("the loser must adopt the committed row, not the identifier it generated itself")
                .isEqualTo(winner.getUuid());
        verify(contentWriter).insertCertificate(any(Certificate.class));
    }

    /**
     * The native insert bypasses both {@code @PrePersist} and the auditing listener, so every column they would have
     * filled has to be stamped by hand. {@code author} is the one no schema constraint would catch.
     */
    @Test
    void stampsTheColumnsTheNativeInsertBypasses() throws Exception {
        when(certificateRepository.findByFingerprint(anyString()))
                .thenReturn(Optional.empty())
                .thenReturn(Optional.of(new Certificate()));

        service.createDiscoveredCertificateAtomic(x509Certificate);

        ArgumentCaptor<Certificate> inserted = ArgumentCaptor.forClass(Certificate.class);
        verify(contentWriter).insertCertificate(inserted.capture());
        assertThat(inserted.getValue()).satisfies(entity -> {
            assertThat(entity.getUuid()).isNotNull();
            assertThat(entity.getCreated()).isNotNull();
            assertThat(entity.getUpdated()).isNotNull();
            assertThat(entity.getFingerprint()).isEqualTo(CertificateUtil.getThumbprint(x509Certificate));
            assertThat(entity.getCertificateContentId()).isEqualTo(11L);
            assertThat(entity.getAuthor())
                    .as("no column constraint would catch this one, so the auditing listener's absence is invisible")
                    .isEqualTo("discovery-operator");
        });
    }

    @Test
    void skipsBothInsertsWhenTheCertificateIsAlreadyKnown() throws Exception {
        Certificate existing = new Certificate();
        existing.setUuid(UUID.randomUUID());
        when(certificateRepository.findByFingerprint(anyString())).thenReturn(Optional.of(existing));

        DiscoveredCertificateImport result = service.createDiscoveredCertificateAtomic(x509Certificate);

        assertThat(result.certificate().getUuid()).isEqualTo(existing.getUuid());
        verify(contentWriter, never()).insertContent(anyString(), anyString());
        verify(contentWriter, never()).insertCertificate(any(Certificate.class));
    }
}

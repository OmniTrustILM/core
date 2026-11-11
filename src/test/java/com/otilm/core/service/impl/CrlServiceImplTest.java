package com.otilm.core.service.impl;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.otilm.api.model.core.authority.CertificateRevocationReason;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.dao.entity.Crl;
import com.otilm.core.dao.entity.CrlEntry;
import com.otilm.core.dao.entity.CrlEntryId;
import com.otilm.core.dao.repository.CrlEntryRepository;
import com.otilm.core.dao.repository.CrlRepository;
import com.otilm.core.dao.repository.X509CertificateRepository;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.service.writer.CrlEntryData;
import com.otilm.core.service.writer.CrlWriter;
import com.otilm.core.service.writer.CrlWriter.CrlWrite;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.crl.CrlDownloadGuard;
import com.otilm.core.util.crl.CrlDownloader;
import com.otilm.core.util.crl.RevokedCertificate;
import jakarta.persistence.EntityManager;
import jakarta.persistence.QueryTimeoutException;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CRLReason;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.util.unit.DataSize;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.otilm.core.util.builders.CrlBuilder.aCrl;
import static com.otilm.core.util.builders.X509CrlBuilder.anX509Crl;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The CRL check's decisions that need a state the integration tests cannot stage, such as a download permit held past
 * the wait, a write another Core instance overtook, or a store that outlasts the download timeout.
 */
@ExtendWith(MockitoExtension.class)
class CrlServiceImplTest {

    private static final String ISSUER_DN = "CN=Crl Service Test CA";
    private static final String BASE_CRL_URL = "http://crl.test/base.crl";
    private static final String DELTA_CRL_URL = "http://crl.test/delta.crl";
    /** The guard waits twice this long for a lock or a permit. */
    private static final Duration SHORT_DOWNLOAD_TIMEOUT = Duration.ofMillis(100);

    private static KeyPair issuerKeyPair;

    @Mock
    private X509CertificateRepository x509CertificateRepository;

    @Mock
    private CrlRepository crlRepository;

    @Mock
    private CrlEntryRepository crlEntryRepository;

    @Mock
    private CrlWriter crlWriter;

    @Mock
    private EntityManager entityManager;

    @Mock
    private CrlDownloader crlDownloader;

    private final AtomicReference<Crl> storedRow = new AtomicReference<>();
    private final AtomicReference<Crl> rowStoredAfterNextRead = new AtomicReference<>();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final CountDownLatch releasePermit = new CountDownLatch(1);
    private CrlDownloadGuard crlDownloadGuard;
    private CrlServiceImpl crlService;

    private static Map<String, OidRecord> savedRdnCache;

    @BeforeAll
    static void createIssuerKeyAndSeedRdnCache() throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        issuerKeyPair = generator.generateKeyPair();
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
    void wireServiceWithOneDownloadPermit() {
        crlDownloadGuard = new CrlDownloadGuard(1, SHORT_DOWNLOAD_TIMEOUT, Duration.ofMinutes(1));
        crlService = new CrlServiceImpl();
        crlService.setX509CertificateRepository(x509CertificateRepository);
        crlService.setCrlRepository(crlRepository);
        crlService.setCrlEntryRepository(crlEntryRepository);
        crlService.setCrlWriter(crlWriter);
        crlService.setEntityManager(entityManager);
        crlService.setCrlDownloader(crlDownloader);
        crlService.setCrlDownloadGuard(crlDownloadGuard);
        // stands in for the CRL table, which the tests of a static step never read
        lenient()
                .when(crlRepository.findByIssuerDnAndSerialNumber(anyString(), anyString()))
                .thenAnswer(invocation -> readStoredRow());
        lenient().when(crlDownloader.downloadTimeout()).thenReturn(Duration.ofMinutes(1));
    }

    @AfterEach
    void releasePermitAndStopExecutor() {
        releasePermit.countDown();
        executor.shutdownNow();
    }

    // ── StoredCrlFallback ────────────────────────────────────────────────────

    @Nested
    class StoredCrlFallback {

        @Test
        void keepsCertificateRevoked_whenPermitWaitTimesOutAndStoredCrlListsIt() throws Exception {
            // given
            X509Certificate certificate = selfSignedCertificate(true);
            storedRow.set(currentBaseCrlWithDueDeltaCrl());
            when(crlEntryRepository.findById(any(CrlEntryId.class))).thenReturn(Optional.of(new CrlEntry()));
            holdTheOnlyDownloadPermit();

            // when
            UUID crlUuid = crlService.getCurrentCrl(certificate, certificate);

            // then
            assertThat(crlUuid).isEqualTo(storedRow.get().getUuid());
            verifyNoInteractions(crlDownloader);
        }

        @Test
        void failsCrlCheck_whenPermitWaitTimesOutAndStoredCrlDoesNotListIt() throws Exception {
            // given
            X509Certificate certificate = selfSignedCertificate(true);
            storedRow.set(currentBaseCrlWithDueDeltaCrl());
            holdTheOnlyDownloadPermit();

            // when
            ThrowingCallable check = () -> crlService.getCurrentCrl(certificate, certificate);

            // then
            assertThatThrownBy(check).isInstanceOf(IOException.class).hasMessageContaining("Too many CRLs");
        }

        @Test
        void keepsCertificateRevoked_whenCrlStoredDuringIssuerWaitListsIt() throws Exception {
            // given
            X509Certificate certificate = selfSignedCertificate(true);
            startAnotherValidationDownloadingTheCrl(certificate);
            Crl storedByTheOtherValidation = currentBaseCrlWithDueDeltaCrl();
            rowStoredAfterNextRead.set(storedByTheOtherValidation);
            when(crlEntryRepository.findById(any(CrlEntryId.class))).thenReturn(Optional.of(new CrlEntry()));

            // when
            UUID crlUuid = crlService.getCurrentCrl(certificate, certificate);

            // then
            assertThat(crlUuid).isEqualTo(storedByTheOtherValidation.getUuid());
        }

        @Test
        void usesCrlStoredDuringIssuerWait_whenTheWaitRunsOut() throws Exception {
            // given
            X509Certificate certificate = selfSignedCertificate(false);
            startAnotherValidationDownloadingTheCrl(certificate);
            Crl storedByTheOtherValidation = currentBaseCrl();
            rowStoredAfterNextRead.set(storedByTheOtherValidation);

            // when
            UUID crlUuid = crlService.getCurrentCrl(certificate, certificate);

            // then
            assertThat(crlUuid).isEqualTo(storedByTheOtherValidation.getUuid());
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        /** Holds the issuer lock and the only download permit in a download that lasts until the test ends. */
        private void startAnotherValidationDownloadingTheCrl(X509Certificate certificate) throws Exception {
            CountDownLatch downloading = new CountDownLatch(1);
            when(crlDownloader.download(eq(BASE_CRL_URL), anyLong())).thenAnswer(invocation -> {
                downloading.countDown();
                awaitRelease();
                throw new IOException("The test ended");
            });
            executor.submit(() -> crlService.getCurrentCrl(certificate, certificate));
            assertThat(downloading.await(5, TimeUnit.SECONDS)).isTrue();
        }

        private void holdTheOnlyDownloadPermit() throws InterruptedException {
            CountDownLatch permitHeld = new CountDownLatch(1);
            executor.submit(() -> crlDownloadGuard.withDownloadPermit(() -> {
                permitHeld.countDown();
                return awaitRelease();
            }));
            assertThat(permitHeld.await(5, TimeUnit.SECONDS)).isTrue();
        }

        private boolean awaitRelease() throws IOException {
            try {
                return releasePermit.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException(e);
            }
        }
    }

    // ── DeltaCrlRace ─────────────────────────────────────────────────────────

    @Nested
    class DeltaCrlRace {

        @Test
        void failsCrlCheck_whenAnotherWriterReplacedTheBaseCrlTheDeltaCrlExtends() throws Exception {
            // given
            X509Certificate certificate = selfSignedCertificate(true);
            Crl stored = currentBaseCrlWithDueDeltaCrl();
            storedRow.set(stored);
            byte[] deltaCrlOfStoredBase = deltaCrl(certificate, stored.getCrlNumber(), 7);
            when(crlDownloader.download(eq(DELTA_CRL_URL), anyLong())).thenReturn(deltaCrlOfStoredBase);
            Crl replacedByAnotherWriter = copyOf(stored);
            replacedByAnotherWriter.setCrlNumber("6");
            when(crlWriter.applyDeltaCrl(any(), any(), any(), any(), any(), any(), any())).thenAnswer(invocation -> {
                storedRow.set(replacedByAnotherWriter);
                return false;
            });

            // when
            ThrowingCallable check = () -> crlService.getCurrentCrl(certificate, certificate);

            // then
            assertThatThrownBy(check)
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("changed while its delta CRL was applied");
        }

        @Test
        void usesNewerCompleteCrl_whenAnotherWriterStoredItWhileTheDeltaCrlWasApplied() throws Exception {
            // given
            X509Certificate certificate = selfSignedCertificate(true);
            Crl stored = currentBaseCrlWithDueDeltaCrl();
            storedRow.set(stored);
            byte[] deltaCrlOfStoredBase = deltaCrl(certificate, stored.getCrlNumber(), 7);
            when(crlDownloader.download(eq(DELTA_CRL_URL), anyLong())).thenReturn(deltaCrlOfStoredBase);
            Crl newerCompleteCrl = copyOf(stored);
            newerCompleteCrl.setCrlNumber("8");
            when(crlWriter.applyDeltaCrl(any(), any(), any(), any(), any(), any(), any())).thenAnswer(invocation -> {
                storedRow.set(newerCompleteCrl);
                return false;
            });

            // when
            UUID crlUuid = crlService.getCurrentCrl(certificate, certificate);

            // then
            assertThat(crlUuid).isEqualTo(newerCompleteCrl.getUuid());
        }

        @Test
        void failsCrlCheck_whenAnotherWriterAppliedAnOlderDeltaCrlThatIsStillCurrent() throws Exception {
            // given
            X509Certificate certificate = selfSignedCertificate(true);
            Crl stored = currentBaseCrlWithDueDeltaCrl();
            storedRow.set(stored);
            byte[] deltaCrlOfStoredBase = deltaCrl(certificate, stored.getCrlNumber(), 7);
            when(crlDownloader.download(eq(DELTA_CRL_URL), anyLong())).thenReturn(deltaCrlOfStoredBase);
            Crl olderCurrentDeltaCrlApplied = copyOf(stored);
            olderCurrentDeltaCrlApplied.setCrlNumberDelta("6");
            olderCurrentDeltaCrlApplied.setNextUpdateDelta(Date.from(Instant.now().plus(Duration.ofDays(1))));
            when(crlWriter.applyDeltaCrl(any(), any(), any(), any(), any(), any(), any())).thenAnswer(invocation -> {
                storedRow.set(olderCurrentDeltaCrlApplied);
                return false;
            });

            // when
            ThrowingCallable check = () -> crlService.getCurrentCrl(certificate, certificate);

            // then
            assertThatThrownBy(check)
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("changed while its delta CRL was applied");
        }
    }

    // ── StoringTheDeltaCrl ───────────────────────────────────────────────────

    @Nested
    class StoringTheDeltaCrl {

        @Test
        void failsCrlCheckWithReason_whenStoringTheDeltaCrlFails() throws Exception {
            // given
            X509Certificate certificate = selfSignedCertificate(true);
            Crl stored = currentBaseCrlWithDueDeltaCrl();
            storedRow.set(stored);
            byte[] deltaCrlOfStoredBase = deltaCrl(certificate, stored.getCrlNumber(), 7);
            when(crlDownloader.download(eq(DELTA_CRL_URL), anyLong())).thenReturn(deltaCrlOfStoredBase);
            when(crlWriter.applyDeltaCrl(any(), any(), any(), any(), any(), any(), any()))
                    .thenThrow(new QueryTimeoutException("canceling statement due to statement timeout"));

            // when
            ThrowingCallable check = () -> crlService.getCurrentCrl(certificate, certificate);

            // then
            assertThatThrownBy(check)
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("The delta CRL could not be stored");
        }

        @Test
        void failsWithoutDownloadingAgain_whenStoringTheDeltaCrlFailedJustBefore() throws Exception {
            // given
            X509Certificate certificate = selfSignedCertificate(true);
            Crl stored = currentBaseCrlWithDueDeltaCrl();
            storedRow.set(stored);
            byte[] deltaCrlOfStoredBase = deltaCrl(certificate, stored.getCrlNumber(), 7);
            when(crlDownloader.download(eq(DELTA_CRL_URL), anyLong())).thenReturn(deltaCrlOfStoredBase);
            when(crlWriter.applyDeltaCrl(any(), any(), any(), any(), any(), any(), any()))
                    .thenThrow(new QueryTimeoutException("canceling statement due to statement timeout"));
            ThrowingCallable firstCheck = () -> crlService.getCurrentCrl(certificate, certificate);
            assertThatThrownBy(firstCheck).isInstanceOf(IOException.class);

            // when
            ThrowingCallable secondCheck = () -> crlService.getCurrentCrl(certificate, certificate);

            // then
            assertThatThrownBy(secondCheck)
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("The delta CRL could not be stored");
            verify(crlDownloader, times(1)).download(eq(DELTA_CRL_URL), anyLong());
        }
    }

    // ── StoringTheCrl ────────────────────────────────────────────────────────

    @Nested
    class StoringTheCrl {

        @Test
        void failsCrlCheckWithReason_whenStoringTheCrlFails() throws Exception {
            // given
            X509Certificate certificate = selfSignedCertificate(false);
            byte[] baseCrl = baseCrl(certificate, 5);
            when(crlDownloader.download(eq(BASE_CRL_URL), anyLong())).thenReturn(baseCrl);
            when(crlWriter.persistCrlAndEntries(any(), anyBoolean(), any(), any()))
                    .thenThrow(new QueryTimeoutException("canceling statement due to statement timeout"));

            // when
            ThrowingCallable check = () -> crlService.getCurrentCrl(certificate, certificate);

            // then
            assertThatThrownBy(check)
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("The CRL could not be stored");
        }

        @Test
        void failsWithoutDownloadingAgain_whenStoringTheCrlFailedJustBefore() throws Exception {
            // given
            X509Certificate certificate = selfSignedCertificate(false);
            byte[] baseCrl = baseCrl(certificate, 5);
            when(crlDownloader.download(eq(BASE_CRL_URL), anyLong())).thenReturn(baseCrl);
            when(crlWriter.persistCrlAndEntries(any(), anyBoolean(), any(), any()))
                    .thenThrow(new QueryTimeoutException("canceling statement due to statement timeout"));
            ThrowingCallable firstCheck = () -> crlService.getCurrentCrl(certificate, certificate);
            assertThatThrownBy(firstCheck).isInstanceOf(IOException.class);

            // when
            ThrowingCallable secondCheck = () -> crlService.getCurrentCrl(certificate, certificate);

            // then
            assertThatThrownBy(secondCheck)
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("The CRL could not be stored");
            verify(crlDownloader, times(1)).download(eq(BASE_CRL_URL), anyLong());
        }

        @Test
        void returnsRowOfAnotherWriter_whenItStoredTheCrlFirst() throws Exception {
            // given
            X509Certificate certificate = selfSignedCertificate(false);
            byte[] baseCrl = baseCrl(certificate, 5);
            when(crlDownloader.download(eq(BASE_CRL_URL), anyLong())).thenReturn(baseCrl);
            Crl storedByAnotherWriter = currentBaseCrl();
            when(crlWriter.persistCrlAndEntries(any(), anyBoolean(), any(), any())).thenAnswer(invocation -> {
                storedRow.set(storedByAnotherWriter);
                return new CrlWrite(storedByAnotherWriter.getUuid(), false);
            });

            // when
            UUID crlUuid = crlService.getCurrentCrl(certificate, certificate);

            // then
            assertThat(crlUuid).isEqualTo(storedByAnotherWriter.getUuid());
        }
    }

    // ── DownloadFailureMemory ────────────────────────────────────────────────

    @Nested
    class DownloadFailureMemory {

        @Test
        void downloadsOtherDistributionPoint_whenOneOfTheIssuerFailedJustBefore() throws Exception {
            // given
            String failingUrl = "http://crl.test/partition-1.crl";
            String otherUrl = "http://crl.test/partition-2.crl";
            X509Certificate namingFailingUrl = selfSignedCertificateNaming(failingUrl);
            X509Certificate namingOtherUrl = selfSignedCertificateNaming(otherUrl);
            when(crlDownloader.download(eq(failingUrl), anyLong())).thenThrow(new IOException("Connection refused"));
            when(crlDownloader.download(eq(otherUrl), anyLong())).thenReturn(baseCrl(namingOtherUrl, 5));
            when(crlWriter.persistCrlAndEntries(any(), anyBoolean(), any(), any()))
                    .thenReturn(new CrlWrite(UUID.randomUUID(), true));
            ThrowingCallable failingCheck = () -> crlService.getCurrentCrl(namingFailingUrl, namingFailingUrl);
            assertThatThrownBy(failingCheck).isInstanceOf(IOException.class);

            // when
            UUID crlUuid = crlService.getCurrentCrl(namingOtherUrl, namingOtherUrl);

            // then
            assertThat(crlUuid).isNotNull();
            verify(crlDownloader).download(eq(otherUrl), anyLong());
        }
    }

    // ── StoredCrlCurrency ────────────────────────────────────────────────────

    @Nested
    class StoredCrlCurrency {

        @Test
        void usesStoredCrlWithoutDownload_whenItsNextUpdatePassedWithinClockSkew() throws Exception {
            // given
            X509Certificate certificate = selfSignedCertificate(false);
            Crl justPastNextUpdate = currentBaseCrl();
            justPastNextUpdate.setNextUpdate(Date.from(Instant.now().minus(Duration.ofMinutes(1))));
            storedRow.set(justPastNextUpdate);

            // when
            UUID crlUuid = crlService.getCurrentCrl(certificate, certificate);

            // then
            assertThat(crlUuid).isEqualTo(justPastNextUpdate.getUuid());
            verifyNoInteractions(crlDownloader);
        }

        @Test
        void usesStoredDeltaCrlWithoutDownload_whenItsNextUpdatePassedWithinClockSkew() throws Exception {
            // given
            X509Certificate certificate = selfSignedCertificate(true);
            Crl deltaJustPastNextUpdate = currentBaseCrl();
            deltaJustPastNextUpdate.setCrlNumberDelta("6");
            deltaJustPastNextUpdate.setNextUpdateDelta(Date.from(Instant.now().minus(Duration.ofMinutes(1))));
            storedRow.set(deltaJustPastNextUpdate);

            // when
            UUID crlUuid = crlService.getCurrentCrl(certificate, certificate);

            // then
            assertThat(crlUuid).isEqualTo(deltaJustPastNextUpdate.getUuid());
            verifyNoInteractions(crlDownloader);
        }
    }

    // ── DownloadDeadline ─────────────────────────────────────────────────────

    @Nested
    class DownloadDeadline {

        @Test
        @Timeout(20)
        void failsWithinOneDownloadTimeout_whenEveryDistributionPointStalls() throws Exception {
            // given
            var downloadTimeout = Duration.ofSeconds(1);
            crlService.setCrlDownloader(new CrlDownloader(1_000, 10_000, DataSize.ofKilobytes(64), downloadTimeout));
            try (ServerSocket silentServer = new ServerSocket(0, 10, InetAddress.getByName(LoopbackWireMock.HOST))) {
                Thread.ofVirtual().start(() -> holdEveryConnectionOpen(silentServer));
                String silentUrl = LoopbackWireMock.url(silentServer.getLocalPort()) + "/ca.crl";
                X509Certificate namingThreeStallingUrls = selfSignedCertificateNaming(silentUrl + "?1",
                        silentUrl + "?2", silentUrl + "?3");

                // when
                long start = System.nanoTime();
                ThrowingCallable check = () -> crlService
                        .getCurrentCrl(namingThreeStallingUrls, namingThreeStallingUrls);

                // then
                assertThatThrownBy(check)
                        .isInstanceOf(IOException.class)
                        .hasMessageContaining("the 1 s for reading the CRL had passed before it was requested");
                assertThat(Duration.ofNanos(System.nanoTime() - start))
                        .as("one deadline for all three URLs, not one each")
                        .isLessThan(Duration.ofMillis(2_500));
            }
        }

        @Test
        @Timeout(20)
        void readsDeltaCrl_whenStoringTheBaseCrlOutlastsTheDownloadTimeout() throws Exception {
            // given
            var downloadTimeout = Duration.ofSeconds(1);
            crlService.setCrlDownloader(new CrlDownloader(1_000, 5_000, DataSize.ofMegabytes(1), downloadTimeout));
            WireMockServer crlServer = LoopbackWireMock.start();
            try {
                String baseUrl = LoopbackWireMock.url(crlServer) + "/base.crl";
                String deltaUrl = LoopbackWireMock.url(crlServer) + "/delta.crl";
                X509Certificate certificate = selfSignedCertificateWithDeltaCrl(deltaUrl, baseUrl);
                crlServer
                        .stubFor(get(urlPathEqualTo("/base.crl"))
                                .willReturn(aResponse().withBody(baseCrl(certificate, 5))));
                crlServer
                        .stubFor(get(urlPathEqualTo("/delta.crl"))
                                .willReturn(aResponse().withBody(deltaCrl(certificate, "5", 7))));
                UUID storedCrlUuid = UUID.randomUUID();
                when(crlWriter.persistCrlAndEntries(any(), anyBoolean(), any(), any())).thenAnswer(invocation -> {
                    takeLongerThan(downloadTimeout);
                    return new CrlWrite(storedCrlUuid, true);
                });
                when(crlWriter.applyDeltaCrl(any(), any(), any(), any(), any(), any(), any())).thenReturn(true);

                // when
                UUID crlUuid = crlService.getCurrentCrl(certificate, certificate);

                // then
                assertThat(crlUuid).isEqualTo(storedCrlUuid);
                verify(crlWriter).applyDeltaCrl(any(), any(), any(), any(), any(), any(), any());
            } finally {
                crlServer.stop();
            }
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        /** Stands in for a store that takes longer than the downloads may, without counting as a download. */
        private static void takeLongerThan(Duration duration) {
            long until = System.nanoTime() + duration.toNanos() + Duration.ofMillis(200).toNanos();
            while (System.nanoTime() - until < 0) {
                LockSupport.parkNanos(until - System.nanoTime());
            }
        }

        /** Accepts every connection and never answers, holding each until its client hangs up. */
        private static void holdEveryConnectionOpen(ServerSocket server) {
            while (!server.isClosed()) {
                try {
                    Socket client = server.accept();
                    Thread.ofVirtual().start(() -> readUntilClientHangsUp(client));
                } catch (IOException serverClosed) {
                    return;
                }
            }
        }

        private static void readUntilClientHangsUp(Socket client) {
            try (client) {
                client.setSoTimeout(20_000);
                client.getInputStream().transferTo(OutputStream.nullOutputStream());
            } catch (IOException connectionEnded) {
                // the client hung up, or the hold limit passed
            }
        }
    }

    // ── StoredRevocationReason ───────────────────────────────────────────────

    @Nested
    class StoredRevocationReason {

        @ParameterizedTest
        @EnumSource(value = CRLReason.class, names = {"UNUSED", "REMOVE_FROM_CRL"})
        void storesUnspecified_whenThePlatformHasNoValueForTheReason(CRLReason reasonWithoutPlatformValue) {
            // given
            var entry = new RevokedCertificate(BigInteger.TEN, new Date(), reasonWithoutPlatformValue);

            // when
            CrlEntryData stored = CrlServiceImpl.toEntryData(entry);

            // then
            assertThat(stored.revocationReason()).isEqualTo(CertificateRevocationReason.UNSPECIFIED.name());
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Reads the stored row, then stores the row a concurrent writer was set to store after that read. */
    private Optional<Crl> readStoredRow() {
        Optional<Crl> read = Optional.ofNullable(storedRow.get()).map(CrlServiceImplTest::copyOf);
        Crl storedByConcurrentWriter = rowStoredAfterNextRead.getAndSet(null);
        if (storedByConcurrentWriter != null) {
            storedRow.set(storedByConcurrentWriter);
        }
        return read;
    }

    private static Crl currentBaseCrl() {
        Crl crl = aCrl()
                .withIssuerDn(ISSUER_DN)
                .withSerialNumber("1")
                .withCrlIssuerDn(ISSUER_DN)
                .withCrlNumber("5")
                .withNextUpdate(Date.from(Instant.now().plus(Duration.ofDays(1))))
                .build();
        crl.setUuid(UUID.randomUUID());
        return crl;
    }

    /** A current base CRL with no delta CRL applied, so a certificate naming a delta CRL needs one downloaded. */
    private static Crl currentBaseCrlWithDueDeltaCrl() {
        return currentBaseCrl();
    }

    private static byte[] baseCrl(X509Certificate issuer, int crlNumber) throws Exception {
        return anX509Crl(issuer.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                .withCrlNumber(BigInteger.valueOf(crlNumber))
                .build()
                .getEncoded();
    }

    private static byte[] deltaCrl(X509Certificate issuer, String baseCrlNumber, int crlNumber) throws Exception {
        return anX509Crl(issuer.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                .withCrlNumber(BigInteger.valueOf(crlNumber))
                .withDeltaCrlIndicator(new BigInteger(baseCrlNumber))
                .build()
                .getEncoded();
    }

    private static Crl copyOf(Crl crl) {
        Crl copy = new Crl();
        copy.setUuid(crl.getUuid());
        copy.setIssuerDn(crl.getIssuerDn());
        copy.setSerialNumber(crl.getSerialNumber());
        copy.setCrlIssuerDn(crl.getCrlIssuerDn());
        copy.setCrlNumber(crl.getCrlNumber());
        copy.setNextUpdate(crl.getNextUpdate());
        copy.setCrlNumberDelta(crl.getCrlNumberDelta());
        copy.setNextUpdateDelta(crl.getNextUpdateDelta());
        copy.setLastRevocationDate(crl.getLastRevocationDate());
        copy.setCaCertificateUuid(crl.getCaCertificateUuid());
        return copy;
    }

    private static X509Certificate selfSignedCertificate(boolean namingDeltaCrl) throws Exception {
        return selfSignedCertificateWithDeltaCrl(namingDeltaCrl ? DELTA_CRL_URL : null, BASE_CRL_URL);
    }

    private static X509Certificate selfSignedCertificateNaming(String... crlUrls) throws Exception {
        return selfSignedCertificateWithDeltaCrl(null, crlUrls);
    }

    /** Names the delta CRL at {@code deltaCrlUrl} unless it is {@code null}. */
    private static X509Certificate selfSignedCertificateWithDeltaCrl(String deltaCrlUrl, String... crlUrls)
            throws Exception {
        X500Name name = new X500Name(ISSUER_DN);
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE, new Date(0),
                Date.from(Instant.parse("9999-12-31T23:59:59Z")), name, issuerKeyPair.getPublic());
        builder.addExtension(Extension.cRLDistributionPoints, false, distributionPoints(crlUrls));
        if (deltaCrlUrl != null) {
            builder.addExtension(Extension.freshestCRL, false, distributionPoints(deltaCrlUrl));
        }
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeyPair.getPrivate())));
    }

    private static CRLDistPoint distributionPoints(String... urls) {
        DistributionPoint[] points = new DistributionPoint[urls.length];
        for (int i = 0; i < urls.length; i++) {
            GeneralName uri = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(urls[i]));
            points[i] = new DistributionPoint(new DistributionPointName(new GeneralNames(uri)), null, null);
        }
        return new CRLDistPoint(points);
    }
}

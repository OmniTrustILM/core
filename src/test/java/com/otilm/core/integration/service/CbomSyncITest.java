package com.otilm.core.integration.service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.MappingBuilder;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.CbomRepositoryException;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.UtilsSettingsDto;
import com.otilm.core.config.CbomSyncProperties;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.cbom.CbomSyncSkip;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.cbom.CbomSyncSkipRepository;
import com.otilm.core.model.cbom.CbomHeaderCounts;
import com.otilm.core.model.cbom.CbomSyncSkipState;
import com.otilm.core.service.CbomInternalService;
import com.otilm.core.service.impl.CbomServiceImpl;
import com.otilm.core.service.writer.cbom.CbomSyncSkipWriter;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ProblemDetail;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The header sync against a stubbed cbom-repository speaking the 0.3.0 feed contract: {@code limit} paging followed
 * through {@code Link rel="next"}, {@code created_at}, {@code cryptoStats: null} with its warning codes, the
 * {@code original} version, and the bounded retry of entries that could not be stored. The older sync tests in
 * {@link CbomServiceITest} keep covering the watermark and the duplicate races.
 */
class CbomSyncITest extends BaseSpringBootTest {

    private static final String SEARCH = "/api/v1/bom";
    private static final String STATS = """
            {"cryptoAssets":{"total":4,"algorithms":{"total":1},"certificates":{"total":1},
             "protocols":{"total":1},"relatedCryptoMaterials":{"total":1}}}""";

    @Autowired
    private CbomInternalService cbomInternalService;

    @Autowired
    private CbomRepository cbomRepository;

    @Autowired
    private CbomSyncSkipRepository skipRepository;

    @Autowired
    private SettingsCache settingsCache;

    @Autowired
    private CbomSyncProperties syncProperties;

    @Autowired
    private CbomSyncSkipWriter skipWriter;

    private WireMockServer repository;
    private PlatformSettingsDto originalSettings;
    private ListAppender<ILoggingEvent> logged;

    @BeforeEach
    void startRepository() {
        originalSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);
        repository = new WireMockServer(0);
        repository.start();
        PlatformSettingsDto settings = new PlatformSettingsDto();
        settings.setUtils(new UtilsSettingsDto());
        settings.getUtils().setCbomRepositoryUrl("http://localhost:" + repository.port());
        settingsCache.cacheSettings(SettingsSection.PLATFORM, settings);

        logged = new ListAppender<>();
        logged.start();
        syncLogger().addAppender(logged);
    }

    @AfterEach
    void stopRepository() {
        try {
            repository.stop();
        } finally {
            settingsCache.cacheSettings(SettingsSection.PLATFORM, originalSettings);
            syncLogger().detachAppender(logged);
            logged.stop();
        }
    }

    // ---- bound properties ----

    @Test
    void theSyncPropertiesBindTheDocumentedDefaults() {
        assertThat(syncProperties.pageSize()).isEqualTo(1000);
        assertThat(syncProperties.overlap()).isEqualTo(Duration.ofSeconds(60));
        assertThat(syncProperties.skippedRetryRuns()).isEqualTo(3);
        assertThat(syncProperties.maxAttempts()).isEqualTo(4);
    }

    // ---- paging ----

    @Test
    void aRunOpensWithAfterAndLimitAndFollowsLinkNextUntilAPageCarriesNone() throws Exception {
        stubPage("after", "0", "[" + entry("urn:uuid:a", "1", STATS, null) + "]", next("c1"));
        stubPage("cursor", "c1", "[" + entry("urn:uuid:b", "1", STATS, null) + "]", next("c2"));
        // one entry and no Link: the absence of the header, not the page size, ends the run
        stubPage("cursor", "c2", "[" + entry("urn:uuid:c", "1", STATS, null) + "]", null);
        stubDocument("urn:uuid:a", 1);
        stubDocument("urn:uuid:b", 1);
        stubDocument("urn:uuid:c", 1);

        String result = cbomInternalService.sync();

        assertThat(cbomRepository.findAll())
                .extracting(Cbom::getSerialNumber)
                .containsExactlyInAnyOrder("urn:uuid:a", "urn:uuid:b", "urn:uuid:c");
        assertThat(result).startsWith("Read 3 entries in 3 pages: stored 3 new entries");
        repository
                .verify(WireMock
                        .getRequestedFor(WireMock.urlPathEqualTo(SEARCH))
                        .withQueryParam("after", WireMock.equalTo("0"))
                        .withQueryParam("limit", WireMock.equalTo("1000")));
        repository
                .verify(WireMock
                        .getRequestedFor(WireMock.urlPathEqualTo(SEARCH))
                        .withQueryParam("cursor", WireMock.equalTo("c1"))
                        .withQueryParam("limit", WireMock.equalTo("1000"))
                        .withQueryParam("after", WireMock.absent()));
        repository
                .verify(0,
                        WireMock
                                .getRequestedFor(WireMock.urlPathEqualTo(SEARCH))
                                .withQueryParam("cursor", WireMock.equalTo("c2"))
                                .withQueryParam("after", WireMock.matching(".*")));
    }

    @Test
    void anEmptyFirstPageIsAValidEmptyRun() throws Exception {
        stubPage("after", "0", "[]", null);

        String result = cbomInternalService.sync();

        assertThat(result).startsWith("Read 0 entries in 1 pages: stored 0 new entries");
        assertThat(cbomRepository.count()).isZero();
    }

    @Test
    void aFailingCursorPageFailsTheRunAndKeepsWhatEarlierPagesStored() throws Exception {
        stubPage("after", "0", "[" + entry("urn:uuid:a", "1", STATS, null) + "]", next("c1"));
        repository
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo(SEARCH))
                        .withQueryParam("cursor", WireMock.equalTo("c1"))
                        .willReturn(problem(400, "unknown parameter cursor")));
        stubDocument("urn:uuid:a", 1);

        assertThatThrownBy(() -> cbomInternalService.sync())
                .isInstanceOf(CbomRepositoryException.class)
                .satisfies(e -> {
                    ProblemDetail problemDetail = ((CbomRepositoryException) e).getProblemDetail();
                    assertThat(problemDetail.getStatus()).isEqualTo(400);
                    // The run's message reaches an operator; the repository's own sentence does not travel with it.
                    assertThat(problemDetail.getDetail())
                            .isEqualTo("CBOM Repository failed a page request (HTTP 400)")
                            .doesNotContain("unknown parameter cursor");
                });

        assertThat(cbomRepository.findAll()).extracting(Cbom::getSerialNumber).containsExactly("urn:uuid:a");
        assertThat(skipRepository.count()).isZero();
    }

    @Test
    void aRepeatedCursorFailsTheRunInsteadOfLooping() throws Exception {
        stubPage("after", "0", "[" + entry("urn:uuid:p1", "1", STATS, null) + "]", next("c1"));
        stubPage("cursor", "c1", "[" + entry("urn:uuid:p2", "1", STATS, null) + "]", next("c2"));
        stubPage("cursor", "c2", "[" + entry("urn:uuid:p3", "1", STATS, null) + "]", next("c1"));
        stubDocument("urn:uuid:p1", 1);
        stubDocument("urn:uuid:p2", 1);
        stubDocument("urn:uuid:p3", 1);

        assertThatThrownBy(() -> cbomInternalService.sync())
                .isInstanceOf(CbomRepositoryException.class)
                .satisfies(e -> {
                    assertThat(((CbomRepositoryException) e).getProblemDetail().getStatus()).isEqualTo(502);
                    assertThat(((CbomRepositoryException) e).getProblemDetail().getDetail())
                            .isEqualTo("CBOM Repository sent a page cursor it had already sent in this run");
                });
        assertThat(cbomRepository.findAll())
                .extracting(Cbom::getSerialNumber)
                .containsExactlyInAnyOrder("urn:uuid:p1", "urn:uuid:p2", "urn:uuid:p3");
    }

    @Test
    void anEmptyPageThatStillClaimsANextPageFailsTheRun() throws Exception {
        stubPage("after", "0", "[" + entry("urn:uuid:a", "1", STATS, null) + "]", next("c1"));
        stubPage("cursor", "c1", "[]", next("c2"));
        stubDocument("urn:uuid:a", 1);

        assertThatThrownBy(() -> cbomInternalService.sync())
                .isInstanceOf(CbomRepositoryException.class)
                .satisfies(e -> assertThat(((CbomRepositoryException) e).getProblemDetail().getDetail())
                        .isEqualTo("CBOM Repository sent an empty page that still claims a next page"));
        assertThat(cbomRepository.findAll()).extracting(Cbom::getSerialNumber).containsExactly("urn:uuid:a");
        repository
                .verify(0,
                        WireMock
                                .getRequestedFor(WireMock.urlPathEqualTo(SEARCH))
                                .withQueryParam("cursor", WireMock.equalTo("c2")));
    }

    @Test
    void anIdentityOfferedTwiceInOneRunIsAttemptedOnceAndTheSecondOfferCountsAsADuplicate() throws Exception {
        // the same entry on two pages of one run (an object overwritten mid-run is re-yielded under its new stamp)
        stubPage("after", "0", "[" + entry("urn:uuid:twice", "1", STATS, null) + "]", next("c1"));
        stubPage("cursor", "c1", "[" + entry("urn:uuid:twice", "1", STATS, null) + "]", null);
        stubDocumentFailure("urn:uuid:twice", 1, 500);

        String result = cbomInternalService.sync();

        assertThat(result)
                .contains("skipped duplicates 1")
                .contains("1 entries could not be stored and were recorded for retry");
        assertThat(onlySkip().getAttempts()).isEqualTo(1);
    }

    // ---- the corrected entry contract ----

    @Test
    void nullCryptoStatsWithMissingOrInvalidWarningsAreStoredWithZeroCountsAndLogged() throws Exception {
        stubPage("after", "0", "[" + entry("urn:uuid:missing", "1", null, "crypto-stats-missing") + ","
                + entry("urn:uuid:invalid", "2", null, "crypto-stats-invalid") + "]", null);
        stubDocument("urn:uuid:missing", 1);
        stubDocument("urn:uuid:invalid", 2);

        String result = cbomInternalService.sync();

        assertThat(result).startsWith("Read 2 entries in 1 pages: stored 2 new entries");
        assertThat(cbomRepository.findAll()).allSatisfy(cbom -> {
            assertThat(cbom.getTotalAssetsCount()).isZero();
            assertThat(cbom.getAlgorithmsCount()).isZero();
        });
        assertThat(skipRepository.count()).isZero();
        assertThat(warnings())
                .anySatisfy(m -> assertThat(m).contains("urn:uuid:missing").contains("crypto-stats-missing"))
                .anySatisfy(m -> assertThat(m).contains("urn:uuid:invalid").contains("crypto-stats-invalid"));
    }

    @Test
    void shallowAndTruncatedWarningsKeepTheReportedCountsAndAreLogged() throws Exception {
        stubPage("after", "0", "[" + entry("urn:uuid:shallow", "1", STATS, "crypto-stats-shallow") + ","
                + entry("urn:uuid:truncated", "1", STATS, "crypto-stats-truncated") + "]", null);
        stubDocument("urn:uuid:shallow", 1);
        stubDocument("urn:uuid:truncated", 1);

        cbomInternalService.sync();

        assertThat(cbomRepository.findAll())
                .hasSize(2)
                .allSatisfy(cbom -> assertThat(cbom.getTotalAssetsCount()).isEqualTo(4));
        assertThat(warnings())
                .anySatisfy(m -> assertThat(m).contains("urn:uuid:shallow").contains("crypto-stats-shallow"))
                .anySatisfy(m -> assertThat(m).contains("urn:uuid:truncated").contains("crypto-stats-truncated"));
    }

    @Test
    void theOriginalUploadIsIgnoredWithoutAReadAndWithoutASkipRecord() throws Exception {
        stubPage("after", "0", "[" + entry("urn:uuid:a", "original", null, "crypto-stats-missing") + ","
                + entry("urn:uuid:a", "1", STATS, null) + "]", null);
        stubDocument("urn:uuid:a", 1);

        String result = cbomInternalService.sync();

        assertThat(result).contains("stored 1 new entries").contains("ignored 1 original documents");
        assertThat(skipRepository.count()).isZero();
        repository
                .verify(0,
                        WireMock
                                .getRequestedFor(WireMock.urlPathEqualTo("/api/v1/bom/urn:uuid:a"))
                                .withQueryParam("version", WireMock.equalTo("original")));
    }

    // ---- bounded retry ----

    @Test
    void anEntryWhoseDocumentCannotBeReadIsRecordedRetriedOnThreeRunsThenPermanentlySkipped() throws Exception {
        stubPage("after", "0", "[" + entry("urn:uuid:bad", "1", STATS, null) + "]", null);
        stubDocumentFailure("urn:uuid:bad", 1, 500);

        String firstRun = cbomInternalService.sync();
        assertThat(firstRun).contains("1 entries could not be stored and were recorded for retry");
        CbomSyncSkip afterFirst = onlySkip();
        assertThat(afterFirst.getAttempts()).isEqualTo(1);
        assertThat(afterFirst.getState()).isEqualTo(CbomSyncSkipState.RETRYING);
        assertThat(afterFirst.getReason()).isEqualTo("repository failed the document read (HTTP 500)");
        assertThat(afterFirst.getTotalAssetsCount()).isEqualTo(4);

        // later runs: the feed no longer offers the entry (watermark moved on); the retry phase does
        stubPage("after", "0", "[]", null);
        for (int run = 2; run <= 3; run++) {
            String result = cbomInternalService.sync();
            assertThat(result)
                    .contains(
                            "retried 1 previously skipped entries, 0 skip records resolved; 0 entries are now permanently skipped");
            assertThat(onlySkip().getAttempts()).isEqualTo(run);
            assertThat(onlySkip().getState()).isEqualTo(CbomSyncSkipState.RETRYING);
        }
        String fourthRun = cbomInternalService.sync();
        // Written off on this run: reported once as given up on, not also as recorded for retry.
        assertThat(fourthRun)
                .contains("0 entries could not be stored and were recorded for retry")
                .contains(
                        "retried 1 previously skipped entries, 0 skip records resolved; 1 entries are now permanently skipped");
        assertThat(onlySkip().getAttempts()).isEqualTo(4);
        assertThat(onlySkip().getState()).isEqualTo(CbomSyncSkipState.PERMANENTLY_SKIPPED);
        assertThat(warnings()).anySatisfy(m -> assertThat(m).contains("urn:uuid:bad").contains("permanently skipped"));

        int readsSoFar = repository
                .countRequestsMatching(
                        WireMock.getRequestedFor(WireMock.urlPathEqualTo("/api/v1/bom/urn:uuid:bad")).build())
                .getCount();
        String fifthRun = cbomInternalService.sync();
        assertThat(fifthRun).contains("retried 0 previously skipped entries");
        assertThat(repository
                .countRequestsMatching(
                        WireMock.getRequestedFor(WireMock.urlPathEqualTo("/api/v1/bom/urn:uuid:bad")).build())
                .getCount()).isEqualTo(readsSoFar);
        assertThat(cbomRepository.count()).isZero();
    }

    @Test
    void aSkippedEntryThatBecomesReadableIsStoredWithTheCountsTheFeedReportedAndItsRecordResolved() throws Exception {
        stubPage("after", "0", "[" + entry("urn:uuid:late", "3", STATS, null) + "]", null);
        stubDocumentFailure("urn:uuid:late", 3, 404);
        cbomInternalService.sync();
        assertThat(onlySkip().getReason()).isEqualTo("document not found in the repository (HTTP 404)");

        stubPage("after", "0", "[]", null);
        stubDocument("urn:uuid:late", 3);
        String result = cbomInternalService.sync();

        assertThat(result).contains("retried 1 previously skipped entries, 1 skip records resolved");
        assertThat(skipRepository.count()).isZero();
        Cbom stored = cbomRepository.findAll().getFirst();
        assertThat(stored.getSerialNumber()).isEqualTo("urn:uuid:late");
        assertThat(stored.getVersion()).isEqualTo(3);
        assertThat(stored.getTotalAssetsCount()).isEqualTo(4);
    }

    @Test
    void aSkippedEntryOfferedAgainByTheFeedIsStoredOnceAndNotRetriedTwiceInTheSameRun() throws Exception {
        stubPage("after", "0", "[" + entry("urn:uuid:again", "1", STATS, null) + "]", null);
        stubDocumentFailure("urn:uuid:again", 1, 500);
        cbomInternalService.sync();
        assertThat(onlySkip().getAttempts()).isEqualTo(1);

        // the overlap re-offers the entry and its document is readable now
        stubDocument("urn:uuid:again", 1);
        String result = cbomInternalService.sync();

        assertThat(result)
                .contains("stored 1 new entries")
                .contains("retried 0 previously skipped entries, 1 skip records resolved");
        assertThat(skipRepository.count()).isZero();
        assertThat(cbomRepository.count()).isEqualTo(1);
    }

    @Test
    void aSkippedEntryOfferedAgainAndFailingAgainCountsOneAttemptForTheRun() throws Exception {
        stubPage("after", "0", "[" + entry("urn:uuid:twice", "1", STATS, null) + "]", null);
        stubDocumentFailure("urn:uuid:twice", 1, 500);

        cbomInternalService.sync();
        String result = cbomInternalService.sync();

        assertThat(result).contains("retried 0 previously skipped entries");
        assertThat(onlySkip().getAttempts()).isEqualTo(2);
    }

    @Test
    void aSingleNewDocumentWhoseReadFailsServerSideIsChargedEvenWithoutOtherReads() throws Exception {
        // One new document in the window and its read never answers: charging it is the only way the watermark can
        // move at all. Failing the run instead would freeze the feed on this one document forever.
        stubPage("after", "0", "[" + entry("urn:uuid:a", "1", STATS, null) + "]", null);
        repository
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/api/v1/bom/urn:uuid:a"))
                        .willReturn(problem(503, "down")));

        String result = cbomInternalService.sync();

        assertThat(result).contains("1 entries could not be stored and were recorded for retry");
        CbomSyncSkip skip = onlySkip();
        assertThat(skip.getSerialNumber()).isEqualTo("urn:uuid:a");
        assertThat(skip.getAttempts()).isEqualTo(1);
        assertThat(skip.getReason()).isEqualTo("repository failed the document read (HTTP 503)");
        assertThat(cbomRepository.count()).isZero();
    }

    @Test
    void anOutageWhereEveryReadFailsServerSideFailsTheRunWithoutChargingTheBudget() throws Exception {
        // Several documents and not one answer: that is the repository, not the documents. The run fails so the
        // watermark holds and the same entries are offered again once it is back.
        stubPage("after", "0",
                "[" + entry("urn:uuid:a", "1", STATS, null) + "," + entry("urn:uuid:b", "1", STATS, null) + "]", null);
        stubDocumentFailure("urn:uuid:a", 1, 503);
        stubDocumentFailure("urn:uuid:b", 1, 503);

        assertThatThrownBy(() -> cbomInternalService.sync())
                .isInstanceOf(CbomRepositoryException.class)
                .satisfies(e -> {
                    assertThat(((CbomRepositoryException) e).getProblemDetail().getStatus()).isEqualTo(503);
                    assertThat(((CbomRepositoryException) e).getProblemDetail().getDetail())
                            .startsWith("CBOM Repository failed every document read of this run (2 documents)");
                });

        assertThat(skipRepository.count()).isZero();
        assertThat(cbomRepository.count()).isZero();
    }

    @Test
    void aServerSideReadFailureIsChargedToThatDocumentWhenOtherReadsSucceed() throws Exception {
        // One document Core never got an answer for, while the repository served the other: that is the document's
        // problem, not an outage, so the run completes and only this entry is charged an attempt.
        stubPage("after", "0",
                "[" + entry("urn:uuid:ok", "1", STATS, null) + "," + entry("urn:uuid:hang", "1", STATS, null) + "]",
                null);
        stubDocument("urn:uuid:ok", 1);
        stubDocumentFailure("urn:uuid:hang", 1, 503);

        String result = cbomInternalService.sync();

        assertThat(result)
                .contains("stored 1 new entries")
                .contains("1 entries could not be stored and were recorded for retry");
        assertThat(cbomRepository.findAll()).extracting(Cbom::getSerialNumber).containsExactly("urn:uuid:ok");
        CbomSyncSkip skip = onlySkip();
        assertThat(skip.getSerialNumber()).isEqualTo("urn:uuid:hang");
        assertThat(skip.getAttempts()).isEqualTo(1);
        assertThat(skip.getReason()).isEqualTo("repository failed the document read (HTTP 503)");
    }

    @Test
    void aPermanentlyHangingDocumentIsWrittenOffAfterTheBudgetEvenWhenTheFeedStaysQuiet() throws Exception {
        // One document that never answers -- a 503, or a read that exceeds the client's response timeout, which is
        // mapped to 503 -- while the feed offers nothing new. If a retry's unanswered read counted as an outage, the
        // run
        // would be skipped every hour, the watermark never recorded again and the budget never spent: the retry the
        // table is meant to bound would be unbounded for exactly the hanging document it was built for.
        stubPage("after", "0", "[" + entry("urn:uuid:hang", "1", STATS, null) + "]", null);
        stubDocumentFailure("urn:uuid:hang", 1, 503);
        cbomInternalService.sync();
        assertThat(onlySkip().getAttempts()).isEqualTo(1);

        stubPage("after", "0", "[]", null);
        for (int run = 2; run <= 3; run++) {
            String result = cbomInternalService.sync();
            assertThat(result).contains("retried 1 previously skipped entries");
            assertThat(onlySkip().getAttempts()).isEqualTo(run);
            assertThat(onlySkip().getState()).isEqualTo(CbomSyncSkipState.RETRYING);
        }

        // The overlap re-offering an entry that is already stored is no evidence either way.
        Cbom alreadyStored = new Cbom();
        alreadyStored.setSerialNumber("urn:uuid:dup");
        alreadyStored.setVersion(1);
        alreadyStored.setSpecVersion("1.6");
        cbomRepository.save(alreadyStored);
        stubPage("after", "0", "[" + entry("urn:uuid:dup", "1", STATS, null) + "]", null);
        String fourthRun = cbomInternalService.sync();

        assertThat(fourthRun).contains("skipped duplicates 1").contains("1 entries are now permanently skipped");
        assertThat(onlySkip().getAttempts()).isEqualTo(4);
        assertThat(onlySkip().getState()).isEqualTo(CbomSyncSkipState.PERMANENTLY_SKIPPED);
        assertThat(onlySkip().getReason()).isEqualTo("repository failed the document read (HTTP 503)");
    }

    @Test
    void aRetryPhaseFailureDoesNotCountTowardsAnOutage() throws Exception {
        stubPage("after", "0", "[" + entry("urn:uuid:later", "1", STATS, null) + "]", null);
        stubDocumentFailure("urn:uuid:later", 1, 500);
        cbomInternalService.sync();
        assertThat(onlySkip().getAttempts()).isEqualTo(1);

        // Two unanswered reads in the run, but only one of them a feed document: the page requests succeeded, so the
        // repository is serving, and a retry's failure is its own. Both are charged and the run completes.
        stubPage("after", "0", "[" + entry("urn:uuid:fresh", "1", STATS, null) + "]", null);
        stubDocumentFailure("urn:uuid:fresh", 1, 503);
        stubDocumentFailure("urn:uuid:later", 1, 503);

        String result = cbomInternalService.sync();

        assertThat(result)
                .contains("2 entries could not be stored and were recorded for retry")
                .contains("retried 1 previously skipped entries");
        List<CbomSyncSkip> skips = skipRepository.findAll();
        assertThat(skips).hasSize(2);
        assertThat(skips)
                .filteredOn(skip -> skip.getSerialNumber().equals("urn:uuid:later"))
                .singleElement()
                .satisfies(skip -> assertThat(skip.getAttempts()).isEqualTo(2));
        assertThat(skips)
                .filteredOn(skip -> skip.getSerialNumber().equals("urn:uuid:fresh"))
                .singleElement()
                .satisfies(skip -> assertThat(skip.getAttempts()).isEqualTo(1));
    }

    @Test
    void aWrittenOffEntryIsStillResolvedWhenItsDocumentFinallyStores() throws Exception {
        // Written-off rows are not loaded by the run any more, so this goes through the per-identity lookup.
        skipWriter
                .recordAttempt("urn:uuid:revived", 1, "reason", CbomHeaderCounts.ZERO,
                        OffsetDateTime.now().truncatedTo(ChronoUnit.MICROS), 1);
        assertThat(onlySkip().getState()).isEqualTo(CbomSyncSkipState.PERMANENTLY_SKIPPED);
        stubPage("after", "0", "[" + entry("urn:uuid:revived", "1", STATS, null) + "]", null);
        stubDocument("urn:uuid:revived", 1);

        String result = cbomInternalService.sync();

        assertThat(result).contains("stored 1 new entries").contains("1 skip records resolved");
        assertThat(skipRepository.count()).isZero();
        assertThat(cbomRepository.count()).isEqualTo(1);
    }

    @Test
    void aServerSideFailureIsChargedInTheRetryPhaseWhenAnotherReadSucceeded() throws Exception {
        stubPage("after", "0", "[" + entry("urn:uuid:later", "1", STATS, null) + "]", null);
        stubDocumentFailure("urn:uuid:later", 1, 500);
        cbomInternalService.sync();
        assertThat(onlySkip().getAttempts()).isEqualTo(1);

        // This run reads one document successfully, so the repository is up and the retry's failure is its own.
        stubPage("after", "0", "[" + entry("urn:uuid:fresh", "1", STATS, null) + "]", null);
        stubDocument("urn:uuid:fresh", 1);
        stubDocumentFailure("urn:uuid:later", 1, 503);

        String result = cbomInternalService.sync();

        assertThat(result).contains("stored 1 new entries");
        assertThat(cbomRepository.findAll()).extracting(Cbom::getSerialNumber).containsExactly("urn:uuid:fresh");
        assertThat(onlySkip().getAttempts()).isEqualTo(2);
        assertThat(onlySkip().getReason()).isEqualTo("repository failed the document read (HTTP 503)");
    }

    @Test
    void anEntryAlreadyInTheDatabaseIsADuplicateWithoutADocumentRead() throws Exception {
        Cbom stored = new Cbom();
        stored.setSerialNumber("urn:uuid:dup");
        stored.setVersion(1);
        stored.setSpecVersion("1.6");
        cbomRepository.save(stored);
        stubPage("after", "0", "[" + entry("urn:uuid:dup", "1", STATS, null) + "]", null);

        String result = cbomInternalService.sync();

        assertThat(result).contains("skipped duplicates 1").contains("stored 0 new entries");
        assertThat(skipRepository.count()).isZero();
        assertThat(cbomRepository.count()).isEqualTo(1);
        repository.verify(0, WireMock.getRequestedFor(WireMock.urlPathEqualTo("/api/v1/bom/urn:uuid:dup")));
    }

    @Test
    void aDocumentWithoutSpecVersionIsRecordedWithCoreShapedReason() throws Exception {
        stubPage("after", "0", "[" + entry("urn:uuid:nospec", "1", STATS, null) + "]", null);
        repository
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/api/v1/bom/urn:uuid:nospec"))
                        .withQueryParam("version", WireMock.equalTo("1"))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"metadata\":{\"component\":{\"name\":\"x\"}}}")));

        cbomInternalService.sync();

        assertThat(onlySkip().getReason())
                .isEqualTo("the stored document was refused: CBOM Repository returned empty specVersion");
        assertThat(cbomRepository.count()).isZero();
    }

    @Test
    void anAlreadyPermanentlySkippedEntryOfferedAgainIsNotCountedAsNewlyPermanent() throws Exception {
        OffsetDateTime now = OffsetDateTime.now().truncatedTo(ChronoUnit.MICROS);
        // already written off
        skipWriter.recordAttempt("urn:uuid:gone", 1, "earlier failure", CbomHeaderCounts.ZERO, now, 1);
        stubPage("after", "0", "[" + entry("urn:uuid:gone", "1", STATS, null) + "]", null);
        stubDocumentFailure("urn:uuid:gone", 1, 500);

        String result = cbomInternalService.sync();

        assertThat(result)
                .contains("0 entries could not be stored and were recorded for retry")
                .contains("0 entries are now permanently skipped")
                .contains("1 offers of permanently skipped entries failed again");
        assertThat(onlySkip().getAttempts()).isEqualTo(2);
        assertThat(onlySkip().getState()).isEqualTo(CbomSyncSkipState.PERMANENTLY_SKIPPED);
        assertThat(warnings())
                .noneSatisfy(m -> assertThat(m).contains("urn:uuid:gone").contains("permanently skipped after"));
    }

    // ---- writer-level state machine ----
    // Timestamps: PostgreSQL stores microseconds, so inputs are truncated with `.truncatedTo(ChronoUnit.MICROS)`
    // and compared through `toInstant()`.

    @Test
    void recordAttemptWithABudgetOfOneWritesTheEntryOffAtOnce() {
        OffsetDateTime now = OffsetDateTime.now().truncatedTo(ChronoUnit.MICROS);

        CbomSyncSkip stored = skipWriter
                .recordAttempt("urn:uuid:budget-one", 1, "reason one", CbomHeaderCounts.ZERO, now, 1);

        assertThat(stored.getAttempts()).isEqualTo(1);
        assertThat(stored.getState()).isEqualTo(CbomSyncSkipState.PERMANENTLY_SKIPPED);
        assertThat(stored.getFirstSkippedAt().toInstant()).isEqualTo(now.toInstant());
        assertThat(stored.getLastAttemptAt().toInstant()).isEqualTo(now.toInstant());
    }

    @Test
    void aSecondAttemptCountsUpKeepsFirstSkippedAtAndTakesTheNewReasonAndCounts() {
        OffsetDateTime first = OffsetDateTime.now().minusHours(1).truncatedTo(ChronoUnit.MICROS);
        OffsetDateTime second = OffsetDateTime.now().truncatedTo(ChronoUnit.MICROS);
        skipWriter.recordAttempt("urn:uuid:twice", 2, "first reason", new CbomHeaderCounts(1, 1, 1, 1, 4), first, 4);

        CbomSyncSkip stored = skipWriter
                .recordAttempt("urn:uuid:twice", 2, "second reason", new CbomHeaderCounts(2, 0, 0, 0, 2), second, 4);

        assertThat(stored.getAttempts()).isEqualTo(2);
        assertThat(stored.getState()).isEqualTo(CbomSyncSkipState.RETRYING);
        assertThat(stored.getFirstSkippedAt().toInstant()).isEqualTo(first.toInstant());
        assertThat(stored.getLastAttemptAt().toInstant()).isEqualTo(second.toInstant());
        assertThat(stored.getReason()).isEqualTo("second reason");
        assertThat(stored.counts()).isEqualTo(new CbomHeaderCounts(2, 0, 0, 0, 2));
        assertThat(skipRepository.count()).isEqualTo(1);
    }

    @Test
    void aWrittenOffRowStaysWrittenOffWhenTheBudgetIsRaisedLater() {
        OffsetDateTime now = OffsetDateTime.now().truncatedTo(ChronoUnit.MICROS);
        skipWriter.recordAttempt("urn:uuid:written-off", 1, "reason", CbomHeaderCounts.ZERO, now, 1);

        CbomSyncSkip stored = skipWriter
                .recordAttempt("urn:uuid:written-off", 1, "reason", CbomHeaderCounts.ZERO, now, 10);

        assertThat(stored.getAttempts()).isEqualTo(2);
        assertThat(stored.getState()).isEqualTo(CbomSyncSkipState.PERMANENTLY_SKIPPED);
    }

    @Test
    void resolveDeletesTheRecordAndReportsWhetherOneExisted() {
        OffsetDateTime now = OffsetDateTime.now().truncatedTo(ChronoUnit.MICROS);
        skipWriter.recordAttempt("urn:uuid:resolved", 1, "reason", CbomHeaderCounts.ZERO, now, 4);

        assertThat(skipWriter.resolve("urn:uuid:resolved", 1)).isEqualTo(1);
        assertThat(skipWriter.resolve("urn:uuid:resolved", 1)).isZero();
        assertThat(skipRepository.count()).isZero();
    }

    // ---- helpers ----

    private static String entry(String serialNumber, String version, String statsJson, String warning) {
        return """
                {"serialNumber":"%s","version":"%s","created_at":"2026-01-25T21:35:05Z","cryptoStats":%s%s}"""
                .formatted(serialNumber, version, statsJson == null ? "null" : statsJson,
                        warning == null ? "" : ",\"warnings\":[\"" + warning + "\"]");
    }

    private static String next(String cursor) {
        return "<bom?cursor=" + cursor + "&limit=1000>; rel=\"next\"";
    }

    private void stubPage(String param, String value, String body, String linkHeader) {
        ResponseDefinitionBuilder response = WireMock
                .aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(body);
        if (linkHeader != null) {
            response = response.withHeader("Link", linkHeader);
        }
        MappingBuilder mapping = WireMock
                .get(WireMock.urlPathEqualTo(SEARCH))
                .withQueryParam(param, WireMock.equalTo(value));
        repository.stubFor(mapping.willReturn(response));
    }

    private void stubDocument(String serialNumber, int version) {
        repository
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/api/v1/bom/" + serialNumber))
                        .withQueryParam("version", WireMock.equalTo(String.valueOf(version)))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody(
                                        "{\"specVersion\":\"1.6\",\"metadata\":{\"timestamp\":\"2026-01-25T21:00:00Z\",\"component\":{\"name\":\"source-"
                                                + serialNumber + "\"}}}")));
    }

    private void stubDocumentFailure(String serialNumber, int version, int status) {
        repository
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/api/v1/bom/" + serialNumber))
                        .withQueryParam("version", WireMock.equalTo(String.valueOf(version)))
                        .willReturn(problem(status, "stubbed failure")));
    }

    private static ResponseDefinitionBuilder problem(int status, String detail) {
        return WireMock
                .aResponse()
                .withStatus(status)
                .withHeader("Content-Type", "application/problem+json")
                .withBody("{\"type\":\"about:blank\",\"title\":\"stub\",\"status\":" + status + ",\"detail\":\""
                        + detail + "\"}");
    }

    private CbomSyncSkip onlySkip() {
        List<CbomSyncSkip> skips = skipRepository.findAll();
        assertThat(skips).hasSize(1);
        return skips.getFirst();
    }

    private List<String> warnings() {
        return logged.list
                .stream()
                .filter(e -> e.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
    }

    private static Logger syncLogger() {
        return (Logger) LoggerFactory.getLogger(CbomServiceImpl.class);
    }
}

package com.otilm.core.service.renewal.refresh;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.connector.v3.certificate.CertificateRenewalInfoResponseDto;
import com.otilm.api.model.connector.v3.certificate.CertificateRenewalInfoResultDtoV3;
import com.otilm.api.model.connector.v3.certificate.CertificateRenewalInfoStatus;
import com.otilm.api.model.core.settings.CertificateSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.core.messaging.jms.configuration.RenewalInfoProperties;
import com.otilm.core.service.SettingInternalService;
import com.otilm.core.service.handler.authority.RenewalInfoCallResult;
import com.otilm.core.service.renewal.RenewalWindowWriter;
import com.otilm.core.service.renewal.Window;
import com.otilm.core.service.renewal.WindowWrite;
import com.otilm.core.service.writer.RenewalRefreshWriter;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.IntFunction;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RenewalInfoResultApplierTest {

    private static final Instant NOW = Instant.parse("2026-11-23T10:00:00Z");
    private static final OffsetDateTime START = OffsetDateTime.of(2026, 12, 1, 0, 0, 0, 0, ZoneOffset.UTC);
    private static final OffsetDateTime END = START.plusDays(2);

    @Mock
    RenewalWindowWriter windowWriter;
    @Mock
    RenewalRefreshWriter refreshWriter;
    @Mock
    SettingInternalService settingService;

    private RenewalInfoResultApplier applier;
    private final UUID certA = UUID.randomUUID();
    private final UUID certB = UUID.randomUUID();
    private final Map<String, UUID> references = Map.of("a", certA, "b", certB);

    @BeforeEach
    void setUp() {
        PlatformSettingsDto platform = new PlatformSettingsDto();
        platform.setCertificates(new CertificateSettingsDto());
        lenient().when(settingService.getPlatformSettingsInternal()).thenReturn(platform);
        lenient().when(windowWriter.writeAuthorityAdvice(any(), any())).thenReturn(true);
        applier = new RenewalInfoResultApplier(windowWriter, refreshWriter, settingService,
                new RenewalInfoProperties(0, 0, 0, null, null, 0), () -> 0.5);
    }

    private static CertificateRenewalInfoResultDtoV3 result(String reference, CertificateRenewalInfoStatus status) {
        CertificateRenewalInfoResultDtoV3 dto = new CertificateRenewalInfoResultDtoV3();
        dto.setReference(reference);
        dto.setStatus(status);
        return dto;
    }

    private static CertificateRenewalInfoResultDtoV3 available(String reference) {
        CertificateRenewalInfoResultDtoV3 dto = result(reference, CertificateRenewalInfoStatus.AVAILABLE);
        dto.setWindowStart(START);
        dto.setWindowEnd(END);
        dto.setExplanationUrl("https://ca.example/why");
        return dto;
    }

    private static RenewalInfoCallResult answered(Integer retryAfter, CertificateRenewalInfoResultDtoV3... results) {
        CertificateRenewalInfoResponseDto response = new CertificateRenewalInfoResponseDto();
        response.setRetryAfter(retryAfter);
        response.setResults(List.of(results));
        return new RenewalInfoCallResult.Answered(response);
    }

    /** The time the writer is told to back the certificate off to when the failure count becomes {@code attempt}. */
    private Instant backOffTime(UUID certificateUuid, int attempt) {
        ArgumentCaptor<IntFunction<Instant>> next = ArgumentCaptor.forClass(IntFunction.class);
        verify(refreshWriter).backOff(eq(certificateUuid), next.capture());
        return next.getValue().apply(attempt);
    }

    @Test
    void availableWritesTheWindowAndSchedulesTheNextRefresh() {
        applier.apply(Map.of("a", certA), answered(null, available("a")), NOW);

        verify(windowWriter)
                .writeAuthorityAdvice(certA, new WindowWrite.Authority(new Window(START.toInstant(), END.toInstant()),
                        "https://ca.example/why"));
        verify(refreshWriter).schedule(certA, NOW.plusSeconds(21600), 0, false);
    }

    @Test
    void availableUsesTheItemRetryAfterBeforeTheResponses() {
        CertificateRenewalInfoResultDtoV3 item = available("a");
        item.setRetryAfter(7200);

        applier.apply(Map.of("a", certA), answered(10000, item), NOW);

        verify(refreshWriter).schedule(certA, NOW.plusSeconds(7200), 0, false);
    }

    @Test
    void availableUsesTheResponseRetryAfterWithoutAnItemValue() {
        applier.apply(Map.of("a", certA), answered(10000, available("a")), NOW);

        verify(refreshWriter).schedule(certA, NOW.plusSeconds(10000), 0, false);
    }

    @Test
    void unknownAndNotSupportedRemoveAdviceAndWaitForTheRecheck() {
        applier
                .apply(references, answered(null, result("a", CertificateRenewalInfoStatus.UNKNOWN),
                        result("b", CertificateRenewalInfoStatus.NOT_SUPPORTED)), NOW);

        verify(windowWriter).writeAuthorityAdvice(certA, new WindowWrite.AuthorityNoAdvice());
        verify(windowWriter).writeAuthorityAdvice(certB, new WindowWrite.AuthorityNoAdvice());
        verify(refreshWriter).schedule(certA, NOW.plusSeconds(604800), 0, true);
        verify(refreshWriter).schedule(certB, NOW.plusSeconds(604800), 0, true);
    }

    @Test
    void retryBacksOffOnTheRampAndCountsTheFailure() {
        applier
                .apply(references, answered(null, result("a", CertificateRenewalInfoStatus.RETRY),
                        result("b", CertificateRenewalInfoStatus.RETRY)), NOW);

        assertEquals(NOW.plus(Duration.ofMinutes(5)), backOffTime(certA, 1));
        assertEquals(NOW.plus(Duration.ofHours(1)), backOffTime(certB, 3));
        verify(windowWriter, never()).writeAuthorityAdvice(any(), any());
    }

    @Test
    void retryAfterOfARetryItemWinsOverTheRamp() {
        CertificateRenewalInfoResultDtoV3 retry = result("a", CertificateRenewalInfoStatus.RETRY);
        retry.setRetryAfter(7200);

        applier.apply(Map.of("a", certA), answered(null, retry), NOW);

        assertEquals(NOW.plusSeconds(7200), backOffTime(certA, 5));
    }

    @Test
    void anItemMissingFromTheResultsBacksOff() {
        applier.apply(references, answered(null, available("a")), NOW);

        verify(refreshWriter).schedule(certA, NOW.plusSeconds(21600), 0, false);
        assertEquals(NOW.plus(Duration.ofMinutes(5)), backOffTime(certB, 1));
    }

    @Test
    void anInvalidWindowBacksOffWithoutWriting() {
        CertificateRenewalInfoResultDtoV3 backwards = available("a");
        backwards.setWindowEnd(START.minusDays(1));
        CertificateRenewalInfoResultDtoV3 incomplete = available("b");
        incomplete.setWindowStart(null);

        applier.apply(references, answered(null, backwards, incomplete), NOW);

        verify(windowWriter, never()).writeAuthorityAdvice(any(), any());
        assertEquals(NOW.plus(Duration.ofMinutes(5)), backOffTime(certA, 1));
        assertEquals(NOW.plus(Duration.ofMinutes(5)), backOffTime(certB, 1));
    }

    @Test
    void aResultWithoutAStatusBacksOff() {
        applier.apply(Map.of("a", certA), answered(null, result("a", null)), NOW);

        assertEquals(NOW.plus(Duration.ofMinutes(5)), backOffTime(certA, 1));
    }

    @Test
    void backOffResultBacksOffEveryItemAndStaysAtTheLastStep() {
        applier.apply(references, new RenewalInfoCallResult.BackOff("unavailable"), NOW);

        assertEquals(NOW.plus(Duration.ofHours(6)), backOffTime(certA, 10));
        assertEquals(NOW.plus(Duration.ofMinutes(5)), backOffTime(certB, 1));
    }

    @Test
    void suspendPostponesTheWholeBatchToTheRecheck() {
        applier.apply(references, new RenewalInfoCallResult.Suspend("test-ca", "not served"), NOW);

        ArgumentCaptor<Collection<UUID>> postponed = ArgumentCaptor.forClass(Collection.class);
        verify(refreshWriter).postpone(postponed.capture(), eq(NOW.plusSeconds(604800)));
        assertEquals(Set.of(certA, certB), Set.copyOf(new ArrayList<>(postponed.getValue())));
        verify(windowWriter, never()).writeAuthorityAdvice(any(), any());
    }

    @Test
    void aFailureOnOneItemDoesNotStopTheOthers() {
        // Lenient: the strict default rejects the call for the other certificate, which does not match this stubbing.
        lenient()
                .doThrow(new IllegalStateException("database down"))
                .when(windowWriter)
                .writeAuthorityAdvice(eq(certA), any());

        applier.apply(references, answered(null, available("a"), available("b")), NOW);

        verify(refreshWriter).schedule(certB, NOW.plusSeconds(21600), 0, false);
        verify(refreshWriter, never()).schedule(eq(certA), any(), anyInt(), anyBoolean());
    }

    @Test
    void settingsOfThePlatformPaceTheRefresh() {
        PlatformSettingsDto platform = new PlatformSettingsDto();
        CertificateSettingsDto certificates = new CertificateSettingsDto();
        certificates.setRenewalInfo(new RenewalInfoSettings(60, 120, 90, 20, 3600).toDto());
        platform.setCertificates(certificates);
        when(settingService.getPlatformSettingsInternal()).thenReturn(platform);

        applier.apply(Map.of("a", certA), answered(null, available("a")), NOW);

        verify(refreshWriter).schedule(certA, NOW.plusSeconds(90), 0, false);
    }

    @Test
    void missingAndInvalidItemsBecomeRetry() {
        UUID missing = UUID.randomUUID();
        UUID duplicated = UUID.randomUUID();
        UUID invalid = UUID.randomUUID();
        UUID valid = UUID.randomUUID();
        Map<String, UUID> requested = Map
                .of("missing", missing, "duplicated", duplicated, "invalid", invalid, "valid", valid);
        CertificateRenewalInfoResultDtoV3 backwards = available("invalid");
        backwards.setWindowEnd(backwards.getWindowStart());

        applier
                .apply(requested, answered(null, available("duplicated"), available("duplicated"), backwards,
                        available("valid"), available("unsent")), NOW);

        verify(windowWriter).writeAuthorityAdvice(eq(valid), any(WindowWrite.Authority.class));
        verify(windowWriter, never()).writeAuthorityAdvice(eq(missing), any());
        verify(windowWriter, never()).writeAuthorityAdvice(eq(duplicated), any());
        verify(windowWriter, never()).writeAuthorityAdvice(eq(invalid), any());
        verify(refreshWriter).schedule(eq(valid), any(), eq(0), eq(false));
        for (UUID retried : List.of(missing, duplicated, invalid)) {
            assertEquals(NOW.plus(Duration.ofMinutes(5)), backOffTime(retried, 1));
        }
        verify(windowWriter, never()).writeAuthorityAdvice(eq(certA), any());
    }

    @Test
    void schedulesNoRefresh_whenTheCertificateNoLongerTakesTheAdvice() {
        // given
        when(windowWriter.writeAuthorityAdvice(eq(certA), any())).thenReturn(false);

        // when
        applier.apply(Map.of("a", certA), answered(null, available("a")), NOW);

        // then
        verify(refreshWriter, never()).schedule(eq(certA), any(), anyInt(), anyBoolean());
        verify(refreshWriter, never()).backOff(eq(certA), any());
    }

    @Test
    void backsOffTheItem_whenTheConnectorAnswersAnUnknownStatus() throws Exception {
        // given
        String unknownStatus = "{\"results\": [{\"reference\": \"a\", \"status\": \"postponed\"}]}";
        CertificateRenewalInfoResponseDto response = new ObjectMapper()
                .findAndRegisterModules()
                .readValue(unknownStatus, CertificateRenewalInfoResponseDto.class);

        // when
        applier.apply(Map.of("a", certA), new RenewalInfoCallResult.Answered(response), NOW);

        // then
        verify(windowWriter, never()).writeAuthorityAdvice(any(), any());
        assertEquals(NOW.plus(Duration.ofMinutes(5)), backOffTime(certA, 1));
    }

    @ParameterizedTest
    @MethodSource("refusedExplanationUrls")
    void storesNoExplanationUrl_whenTheAuthorityGivesAnUnusableOne(String unusableUrl) {
        // given
        CertificateRenewalInfoResultDtoV3 item = available("a");
        item.setExplanationUrl(unusableUrl);

        // when
        applier.apply(Map.of("a", certA), answered(null, item), NOW);

        // then
        verify(windowWriter)
                .writeAuthorityAdvice(certA,
                        new WindowWrite.Authority(new Window(START.toInstant(), END.toInstant()), null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://ca.example/why", "HTTP://ca.example/why?id=1"})
    void keepsTheExplanationUrl_whenItIsAnAbsoluteWebUrl(String webUrl) {
        // given
        CertificateRenewalInfoResultDtoV3 item = available("a");
        item.setExplanationUrl(webUrl);

        // when
        applier.apply(Map.of("a", certA), answered(null, item), NOW);

        // then
        verify(windowWriter)
                .writeAuthorityAdvice(certA,
                        new WindowWrite.Authority(new Window(START.toInstant(), END.toInstant()), webUrl));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static Stream<Arguments> refusedExplanationUrls() {
        String tooLong = "https://ca.example/" + "a".repeat(2048);
        return Stream
                .of(Arguments.of(Named.of("script URL", "javascript:alert(1)")),
                        Arguments.of(Named.of("relative URL", "/why")),
                        Arguments.of(Named.of("other scheme", "ftp://ca.example/why")),
                        Arguments.of(Named.of("no host", "https:///why")),
                        Arguments.of(Named.of("not a URL", "https://ca example/why")),
                        Arguments.of(Named.of("longer than the column allows", tooLong)));
    }
}

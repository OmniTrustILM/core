package com.otilm.core.integration.service.renewal;

import com.otilm.api.model.client.certificate.CertificateResponseDto;
import com.otilm.api.model.client.certificate.CertificateSearchRequestDto;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.RenewalWindowSource;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.FilterFieldType;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.workflows.ConditionItem;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.evaluator.CertificateTriggerEvaluator;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.renewal.RenewalWindowWriter;
import com.otilm.core.service.renewal.Window;
import com.otilm.core.service.renewal.WindowWrite;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SearchHelper;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyEqualsFilter;
import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyFilter;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The renewal window fields read the certificate's renewal row through a join, which a certificate may not have: a
 * search keeps such a certificate out of a match, and a condition finds the value absent.
 */
class FilterFieldRenewalITest extends BaseSpringBootTest {

    private static final Duration WINDOW_LENGTH = Duration.ofDays(14);
    private static final DateTimeFormatter CONDITION_DATETIME = DateTimeFormatter
            .ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");

    @Autowired
    private CertificateExternalService certificateService;
    @Autowired
    private CertificateTriggerEvaluator certificateTriggerEvaluator;
    @Autowired
    private RenewalWindowWriter renewalWindowWriter;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;

    private Certificate forced;
    private Certificate laterPolicy;
    private Certificate withoutRow;

    @BeforeEach
    void seedCertificates() {
        Instant now = Instant.now();
        forced = seedCertificate();
        renewalWindowWriter
                .write(forced.getUuid(), new WindowWrite.Forced(
                        new Window(now.minus(Duration.ofDays(1)), now.plus(WINDOW_LENGTH)), null));
        laterPolicy = seedCertificate();
        Instant laterStart = now.plus(Duration.ofDays(10));
        renewalWindowWriter
                .write(laterPolicy.getUuid(),
                        new WindowWrite.Policy(new Window(laterStart, laterStart.plus(WINDOW_LENGTH))));
        withoutRow = seedCertificate();
    }

    @Test
    void findsCertificatesWhoseWindowStartsInTheRange_whenSearchingByWindowStart() throws Exception {
        // given
        Instant now = Instant.now();
        var rangeStart = aPropertyFilter(FilterField.RENEWAL_WINDOW_START, FilterConditionOperator.GREATER_OR_EQUAL,
                formatted(now.plus(Duration.ofDays(5))));
        var rangeEnd = aPropertyFilter(FilterField.RENEWAL_WINDOW_START, FilterConditionOperator.LESSER,
                formatted(now.plus(Duration.ofDays(20))));

        // when
        List<UUID> found = search(rangeStart, rangeEnd);

        // then
        assertThat(found).containsExactly(laterPolicy.getUuid());
    }

    @Test
    void findsForcedWindows_whenSearchingBySource() throws Exception {
        // given
        var forcedSource = aPropertyEqualsFilter(FilterField.RENEWAL_WINDOW_SOURCE,
                RenewalWindowSource.FORCED.getCode());

        // when
        List<UUID> found = search(forcedSource);

        // then
        assertThat(found).containsExactly(forced.getUuid());
    }

    @Test
    void matchesTheCondition_whenTheWindowIsForced() {
        // given
        UUID certificateUuid = forced.getUuid();

        // when
        boolean matched = evaluate(certificateUuid, FilterField.RENEWAL_WINDOW_SOURCE, FilterConditionOperator.EQUALS,
                List.of(RenewalWindowSource.FORCED.getCode()));

        // then
        assertThat(matched).isTrue();
    }

    @Test
    void doesNotMatchTheCondition_whenTheCertificateHasNoRenewalRow() {
        // given
        UUID certificateUuid = withoutRow.getUuid();

        // when
        boolean matched = evaluate(certificateUuid, FilterField.RENEWAL_WINDOW_SOURCE, FilterConditionOperator.EQUALS,
                List.of(RenewalWindowSource.FORCED.getCode()));

        // then
        assertThat(matched).isFalse();
    }

    @Test
    void matchesTheCondition_whenTheWindowStartedBeforeTheGivenTime() {
        // given
        String now = formatted(Instant.now());

        // when
        boolean matched = evaluate(forced.getUuid(), FilterField.RENEWAL_WINDOW_START,
                FilterConditionOperator.LESSER_OR_EQUAL, now);

        // then
        assertThat(matched).isTrue();
    }

    @Test
    void describesTheSourceByItsValues_whenPreparingTheSourceField() {
        // given — the source field lists the constants of RenewalWindowSource

        // when
        SearchFieldDataDto sourceField = SearchHelper.prepareSearch(FilterField.RENEWAL_WINDOW_SOURCE);

        // then
        assertThat(sourceField.getType()).isEqualTo(FilterFieldType.LIST);
        assertThat(sourceField.getValue())
                .isEqualTo(List
                        .of(RenewalWindowSource.AUTHORITY.getCode(), RenewalWindowSource.FORCED.getCode(),
                                RenewalWindowSource.POLICY.getCode()));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Certificate seedCertificate() {
        CertificateContent content = new CertificateContent();
        content.setContent(UUID.randomUUID().toString());
        content = certificateContentRepository.save(content);
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Certificate certificate = aCertificate()
                .withSubjectDn("CN=renewal-filter")
                .withSerialNumber(UUID.randomUUID().toString())
                .withFingerprint(UUID.randomUUID().toString())
                .withState(CertificateState.ISSUED)
                .withCertificateContent(content)
                .withCertificateContentId(content.getId())
                .withNotBefore(Date.from(now.minus(Duration.ofDays(60))))
                .withNotAfter(Date.from(now.plus(Duration.ofDays(60))))
                .build();
        return certificateRepository.save(certificate);
    }

    private List<UUID> search(SearchFilterRequestDto... filters) throws Exception {
        CertificateSearchRequestDto request = new CertificateSearchRequestDto();
        request.setFilters(List.of(filters));
        CertificateResponseDto response = certificateService.listCertificates(new SecurityFilter(), request);
        return response.getCertificates().stream().map(CertificateDto::getUuid).map(UUID::fromString).toList();
    }

    private boolean evaluate(UUID certificateUuid, FilterField field, FilterConditionOperator operator, Object value) {
        ConditionItem condition = new ConditionItem();
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        condition.setFieldIdentifier(field.name());
        condition.setOperator(operator);
        condition.setValue(value);
        Boolean matched = new TransactionTemplate(transactionManager).execute(status -> {
            Certificate certificate = certificateRepository.findByUuid(certificateUuid).orElseThrow();
            try {
                return certificateTriggerEvaluator.evaluateConditionItem(condition, certificate, Resource.CERTIFICATE);
            } catch (Exception e) {
                throw new AssertionError("%s %s could not be evaluated".formatted(field, operator), e);
            }
        });
        return Boolean.TRUE.equals(matched);
    }

    private static String formatted(Instant instant) {
        return CONDITION_DATETIME.format(instant.atZone(ZoneId.systemDefault()));
    }
}

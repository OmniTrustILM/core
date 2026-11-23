package com.otilm.core.util.ai;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.certificate.CertificateSearchRequestDto;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.enums.FilterField;
import com.otilm.core.security.ai.AiReadInvocationContext;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.handler.StoredCertificateHealth;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.security.core.context.SecurityContextHolder;

/** Test-only two-operation boundary; no production caller or tool registry. */
public final class CertificateReadProofAdapter {
    private static final ObjectMapper PARSER = parser();
    private static final Instant MIN_EXPIRY = Instant.parse("0001-01-01T00:00:00Z");
    private static final Instant AFTER_MAX_EXPIRY = Instant.parse("+10000-01-01T00:00:00Z");
    private final CertificateExternalService service;
    private final Clock clock;

    public record SearchArguments(int page, int pageSize, Set<CertificateState> states,
            Set<CertificateValidationStatus> validationStatuses, Instant expiresBefore) {
        public SearchArguments {
            if (page < 1 || page > 10 || pageSize < 1 || pageSize > 100 || (states != null && states.isEmpty())
                    || (validationStatuses != null && validationStatuses.isEmpty())
                    || (expiresBefore != null && (expiresBefore.getNano() % 1_000_000 != 0
                            || expiresBefore.isBefore(MIN_EXPIRY) || !expiresBefore.isBefore(AFTER_MAX_EXPIRY)))) {
                throw new IllegalArgumentException("Invalid certificate read arguments");
            }
            states = states == null ? null : Set.copyOf(states);
            validationStatuses = validationStatuses == null ? null : Set.copyOf(validationStatuses);
        }
    }

    public record StoredHealthArguments(UUID certificateUuid) {
    }

    public record Failure(String error) {
    }

    public record SafeCertificate(UUID certificateUuid, UUID raProfileUuid, String commonName, String serialNumber,
            String issuerCommonName, String fingerprint, Instant notBefore, Instant notAfter, CertificateState state,
            CertificateValidationStatus validationStatus) {
    }

    public record SearchResult(int page, int pageSize, long totalItems, int totalPages,
            List<SafeCertificate> certificates) {
        public SearchResult {
            certificates = List.copyOf(certificates);
        }
    }

    public enum Freshness {
        CURRENT,
        STALE,
        MISSING,
        INCONSISTENT
    }

    public record ReportEntry(StoredCertificateHealth stored, Freshness freshness) {
    }

    public record Report(UUID raProfileUuid, int trustedCertificateCount, int pagesRead, long observedTotal,
            boolean allPagesRead, boolean stoppedAtLimit, String evidenceBasis, List<ReportEntry> certificates) {
        public Report {
            certificates = List.copyOf(certificates);
        }
    }

    public CertificateReadProofAdapter(CertificateExternalService service, Clock clock) {
        this.service = service;
        this.clock = clock;
    }

    public Object dispatch(String input) {
        JsonNode envelope;
        try {
            envelope = parseInput(input);
            fields(envelope, Set.of("tool", "arguments"));
            String tool = text(envelope.path("tool"));
            JsonNode arguments = envelope.path("arguments");
            return switch (tool) {
                case "certificate.search" -> executeSearch(parseSearch(arguments));
                case "certificate.storedHealth" -> executeStored(parseStored(arguments));
                default -> new Failure("Invalid certificate read arguments");
            };
        } catch (Exception failure) {
            return new Failure("Invalid certificate read arguments");
        }
    }

    static JsonNode parseInput(String input) throws java.io.IOException {
        if (input == null || input.length() > 1048576 || input.getBytes(StandardCharsets.UTF_8).length > 1048576) {
            throw new IllegalArgumentException();
        }
        return PARSER.readTree(input);
    }

    private Object executeSearch(SearchArguments arguments) {
        try {
            return search(arguments);
        } catch (Exception failure) {
            return new Failure("Certificate read unavailable");
        }
    }

    private Object executeStored(StoredHealthArguments arguments) {
        try {
            return stored(arguments);
        } catch (Exception failure) {
            return new Failure("Certificate read unavailable");
        }
    }

    private SearchResult search(SearchArguments args) {
        checkBudget();
        var request = new CertificateSearchRequestDto();
        request.setPageNumber(args.page());
        request.setItemsPerPage(args.pageSize());
        request.setIncludeArchived(false);
        var filters = new ArrayList<SearchFilterRequestDto>();
        if (args.states() != null) {
            filters
                    .add(new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.CERTIFICATE_STATE.name(),
                            FilterConditionOperator.EQUALS,
                            new ArrayList<>(args.states().stream().map(CertificateState::getCode).toList())));
        }
        if (args.validationStatuses() != null) {
            filters
                    .add(new SearchFilterRequestDto(FilterFieldSource.PROPERTY,
                            FilterField.CERTIFICATE_VALIDATION_STATUS.name(), FilterConditionOperator.EQUALS,
                            new ArrayList<>(args
                                    .validationStatuses()
                                    .stream()
                                    .map(CertificateValidationStatus::getCode)
                                    .toList())));
        }
        if (args.expiresBefore() != null) {
            String utc = DateTimeFormatter
                    .ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSSXXX")
                    .withZone(ZoneOffset.UTC)
                    .format(args.expiresBefore());
            filters
                    .add(new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.NOT_AFTER.name(),
                            FilterConditionOperator.LESSER, utc));
        }
        request.setFilters(filters);
        var response = service.listCertificates(SecurityFilter.create(), request);
        var result = new SearchResult(response.getPageNumber(), response.getItemsPerPage(), response.getTotalItems(),
                response.getTotalPages(),
                response.getCertificates().stream().map(CertificateReadProofAdapter::safe).toList());
        checkBudget();
        return result;
    }

    private StoredCertificateHealth stored(StoredHealthArguments arguments)
            throws com.otilm.api.exception.NotFoundException {
        var context = AiReadInvocationContext.current().orElseThrow();
        var result = service
                .getStoredCertificateHealth(SecuredParentUUID.fromUUID(context.scope().raProfileUuid()),
                        SecuredUUID.fromUUID(arguments.certificateUuid()));
        checkBudget();
        return result;
    }

    /**
     * Observations across advertised pages, not a snapshot or complete inventory. Stable totals neither establish
     * unchanged membership nor align a page's selection with its later count. Changes within that window, including
     * count changes, or equal-cardinality membership changes may go undetected; freshness is only illustrative.
     */
    public Report report(SearchArguments arguments) throws com.otilm.api.exception.NotFoundException {
        if (arguments.page() != 1) {
            throw new IllegalArgumentException("Invalid certificate read arguments");
        }
        var context = AiReadInvocationContext.current().orElseThrow();
        var entries = new ArrayList<ReportEntry>();
        var seen = new HashSet<UUID>();
        long total = 0;
        int totalPages = 0;
        int page = 1;
        int pages = 0;
        boolean allPagesRead = false;
        while (page <= 10 && entries.size() < 100) {
            var result = search(new SearchArguments(page, arguments.pageSize(), arguments.states(),
                    arguments.validationStatuses(), arguments.expiresBefore()));
            pages++;
            if (pages == 1) {
                total = result.totalItems();
                totalPages = result.totalPages();
            } else if (total != result.totalItems() || totalPages != result.totalPages()) {
                throw new IllegalStateException("Certificate read unavailable");
            }
            for (var certificate : result.certificates()) {
                if (!seen.add(certificate.certificateUuid())) {
                    throw new IllegalStateException("Certificate read unavailable");
                }
                var stored = stored(new StoredHealthArguments(certificate.certificateUuid()));
                entries.add(new ReportEntry(stored, freshness(stored)));
            }
            if (page >= totalPages) {
                allPagesRead = true;
                break;
            }
            page++;
        }
        checkBudget();
        return new Report(context.scope().raProfileUuid(), context.scope().certificateUuids().size(), pages, total,
                allPagesRead, !allPagesRead, "OBSERVATIONS", entries);
    }

    private Freshness freshness(StoredCertificateHealth stored) {
        var time = stored.validationTimestamp();
        Instant now = clock.instant();
        if (time != null && time.toInstant().isAfter(now)) {
            return Freshness.INCONSISTENT;
        }
        if (stored.evidence() != StoredCertificateHealth.Evidence.PRESENT || time == null) {
            return Freshness.MISSING;
        }
        return time.toInstant().isBefore(now.minus(Duration.ofHours(24))) ? Freshness.STALE : Freshness.CURRENT;
    }

    private static SafeCertificate safe(CertificateDto value) {
        return new SafeCertificate(UUID.fromString(value.getUuid()), UUID.fromString(value.getRaProfile().getUuid()),
                value.getCommonName(), value.getSerialNumber(), value.getIssuerCommonName(), value.getFingerprint(),
                value.getNotBefore() == null ? null : value.getNotBefore().toInstant(),
                value.getNotAfter() == null ? null : value.getNotAfter().toInstant(), value.getState(),
                value.getValidationStatus());
    }

    private static SearchArguments parseSearch(JsonNode node) {
        fields(node, Set.of("page", "pageSize", "states", "validationStatuses", "expiresBefore"));
        Instant expiry = node.has("expiresBefore") ? Instant.parse(text(node.get("expiresBefore"))) : null;
        return new SearchArguments(integer(node.path("page")), integer(node.path("pageSize")),
                optionalSet(node, "states", CertificateState::findByCode),
                optionalSet(node, "validationStatuses", CertificateValidationStatus::findByCode), expiry);
    }

    private static StoredHealthArguments parseStored(JsonNode node) {
        fields(node, Set.of("certificateUuid"));
        String value = text(node.path("certificateUuid"));
        UUID uuid = UUID.fromString(value);
        if (!uuid.toString().equalsIgnoreCase(value)) {
            throw new IllegalArgumentException();
        }
        return new StoredHealthArguments(uuid);
    }

    private static <T> Set<T> optionalSet(JsonNode object, String name, Function<String, T> parse) {
        if (!object.has(name)) {
            return null;
        }
        var array = object.get(name);
        if (!array.isArray() || array.isEmpty()) {
            throw new IllegalArgumentException();
        }
        var values = new HashSet<T>();
        array.forEach(value -> {
            if (!values.add(parse.apply(text(value)))) {
                throw new IllegalArgumentException();
            }
        });
        return Set.copyOf(values);
    }

    private static int integer(JsonNode value) {
        if (!value.isIntegralNumber() || !value.canConvertToInt()) {
            throw new IllegalArgumentException();
        }
        return value.intValue();
    }

    private static String text(JsonNode value) {
        if (!value.isTextual()) {
            throw new IllegalArgumentException();
        }
        return value.textValue();
    }

    private static void fields(JsonNode object, Set<String> allowed) {
        if (object == null || !object.isObject()) {
            throw new IllegalArgumentException();
        }
        object.fieldNames().forEachRemaining(name -> {
            if (!allowed.contains(name)) {
                throw new IllegalArgumentException();
            }
        });
    }

    private static void checkBudget() {
        AiReadInvocationContext
                .current()
                .orElseThrow()
                .requirePinnedActor(SecurityContextHolder.getContext().getAuthentication());
    }

    private static ObjectMapper parser() {
        var mapper = ObjectMapperFactory
                .storage()
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                .disable(JsonParser.Feature.INCLUDE_SOURCE_IN_LOCATION);
        mapper
                .getFactory()
                .setStreamReadConstraints(StreamReadConstraints
                        .builder()
                        .maxNestingDepth(32)
                        .maxStringLength(65536)
                        .maxNameLength(128)
                        .maxNumberLength(64)
                        .build());
        return mapper;
    }
}

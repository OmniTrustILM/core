package com.otilm.core.cbom.asset.identity;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Folds an ISO-8601 instant to epoch seconds, so a spelling cannot split a row.
 *
 * <p>
 * Producers write the same instant several ways: {@code 2025-01-01T00:00:00Z} and {@code 2025-01-01T00:00:00.000Z}
 * split one certificate across two rows when hashed verbatim. Sub-second precision is discarded deliberately -- X.509
 * validity has one-second granularity, so it carries no identity.
 *
 * <p>
 * The same normalization applies wherever validity is <em>compared</em> and not only where it is hashed. The
 * digest-refutation index once compared raw strings, so a millisecond suffix could refute a sound digest and push both
 * certificates down a tier.
 */
public final class ValidityTimestamps {

    /**
     * A fractional second, and nothing else that happens to contain a dot.
     *
     * <p>
     * Anchored to a time of day so a version-shaped value keeps its own spelling: an unanchored {@code \.\d+} turned
     * {@code v1.2.3} into {@code v1} and {@code release.1} into {@code release}, merging values that name different
     * things. Both spellings this class accepts are anchored -- the extended {@code T15:16:00} form and the basic
     * fourteen-digit one -- because {@code uuuuMMddHHmmss'Z'} is GeneralizedTime, where a fraction is legal.
     */
    private static final Pattern FRACTION = Pattern.compile("([Tt]\\d{2}:\\d{2}:\\d{2}|\\d{14})\\.\\d+");

    /**
     * Parsed case-insensitively, because the reference's parser is. RFC 3339 permits a lowercase {@code t} separator
     * and a lowercase {@code z} zone, and real producers emit both -- the reference folds only the {@code z} explicitly
     * and gets the {@code t} for free from a case-insensitive matcher. A case-sensitive Java formatter would leave
     * {@code 2025-01-01t00:00:00z} unparsed, keying it on its spelling instead of on its instant.
     */
    private static final List<DateTimeFormatter> OFFSET_FORMATS = List
            .of(caseInsensitiveOffset("+HH:MM"), caseInsensitive("uuuu-MM-dd'T'HH:mm:ssZ"));

    private static final List<DateTimeFormatter> LOCAL_FORMATS = List
            .of(caseInsensitive("uuuu-MM-dd'T'HH:mm:ss'Z'"), caseInsensitive("uuuuMMddHHmmss'Z'"));

    private static DateTimeFormatter caseInsensitive(String pattern) {
        return new DateTimeFormatterBuilder()
                .parseCaseInsensitive()
                .appendPattern(pattern)
                .toFormatter()
                .withResolverStyle(ResolverStyle.STRICT);
    }

    private static DateTimeFormatter caseInsensitiveOffset(String offsetPattern) {
        return new DateTimeFormatterBuilder()
                .parseCaseInsensitive()
                .appendPattern("uuuu-MM-dd'T'HH:mm:ss")
                .appendOffset(offsetPattern, "Z")
                .toFormatter()
                .withResolverStyle(ResolverStyle.STRICT);
    }

    private ValidityTimestamps() {
    }

    /**
     * Epoch seconds as a bare string, or the cleaned input when it parses as no known instant.
     *
     * <p>
     * An unparseable value is returned rather than discarded: it is still a fact the producer stated, and two
     * certificates differing only in an unparseable validity must not merge. The empty string means absent, which is
     * distinct from every present value.
     *
     * <p>
     * <b>An unparseable value is returned exactly as written</b>, stripped of surrounding whitespace and nothing else.
     * The fraction-stripping and zone-case folding apply only to the parse attempt, so the two guarantees this class
     * advertises -- that sub-second precision carries no identity, and that a spelling cannot key a value -- hold for
     * the set of values that parse and not beyond it. {@code 2025-02-30T00:00:00Z}, {@code 2025-02-30T00:00:00.000Z}
     * and {@code 2025-02-30t00:00:00z} are one calendar-invalid date in three spellings, and they key three ways.
     *
     * <p>
     * Returning {@code parseCandidate} instead would put the unconditional {@code z -> Z} fold back on every
     * unparseable value: {@code zebra-2025} keys as {@code Zebra-2025} and {@code cert-z-serial} as
     * {@code cert-Z-serial}, which is the {@code main} defect the previous round closed. The anchored {@link #FRACTION}
     * already protects {@code release.1} and {@code v1.2.3} -- measured directly at this head, both are returned
     * untouched -- so it is the zone fold, not the fraction strip, that puts the two arms in tension.
     *
     * <p>
     * A third arm exists: strip the fraction on the fallback and do <em>not</em> fold the zone case. That folds
     * {@code .000Z} onto {@code Z}, leaves {@code zebra-2025} alone, and leaves only the lowercase spelling keying
     * apart. It is a real option, declined because "returned exactly as written" is a contract a reader can hold in one
     * sentence and "fraction stripped, case kept" is not, and because the corpus carries zero rows either way.
     */
    public static String normalize(String raw) {
        if (raw == null || AsciiText.isBlank(raw)) {
            return "";
        }
        String cleaned = AsciiText.strip(raw);
        String parseCandidate = FRACTION.matcher(cleaned).replaceAll("$1").replace("z", "Z");
        for (DateTimeFormatter format : OFFSET_FORMATS) {
            try {
                return Long.toString(OffsetDateTime.parse(parseCandidate, format).toEpochSecond());
            } catch (DateTimeParseException e) {
                // Not this offset spelling. The local spellings are tried below, and a value matching none is returned
                // cleaned rather than dropped.
            }
        }
        for (DateTimeFormatter format : LOCAL_FORMATS) {
            try {
                return Long
                        .toString(
                                LocalDateTime.parse(parseCandidate, format).toInstant(ZoneOffset.UTC).getEpochSecond());
            } catch (DateTimeParseException e) {
                // As above.
            }
        }
        return cleaned;
    }

    /** Parses to an instant where one is wanted rather than a keyed string. Absent when the value is unparseable. */
    public static Instant instant(String raw) {
        String normalized = normalize(raw);
        try {
            return normalized.isEmpty() ? null : Instant.ofEpochSecond(Long.parseLong(normalized));
        } catch (NumberFormatException e) {
            return null;
        }
    }
}

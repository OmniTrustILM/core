/**
 * Golden-file JSON tests baselining Jackson 2 output ahead of the Spring Boot 4.1 / Jackson 3 migration. Jackson 3
 * changes defaults no compiler catches, and tests asserting on objects rather than on JSON pass straight through them.
 *
 * <p>
 * Covered surfaces, in descending blast radius: {@code jsonb} columns, the {@code ResponseAttributeSerializer}
 * redaction, the shapes {@code OutboundSecretContainment} inspects, the {@code @JsonTypeInfo} hierarchies shared with
 * ~40 connector repositories, and the REST/ACME wire contracts.
 *
 * <h2>Hand-written serializers</h2> The {@code interfaces} library writes against Jackson 2 internals, and which of its
 * serializers run is not visible from the annotations:
 * <ul>
 * <li>{@code ResponseAttributeSerializer} — live and security-critical; declared on the
 * {@code ResponseAttributeV2.content} <i>field</i>, so the subclass cancellation below does not reach it.</li>
 * <li>{@code AttributeContentDeserializer} — live; picks the v2 or v3 content model from whether {@code contentType} is
 * present.</li>
 * <li>{@code BaseAttributeDeserializer} — live; it, not {@code @JsonSubTypes}, resolves an attribute's concrete
 * class.</li>
 * <li>{@code BaseAttributeSerializer} — live only under a declared type that does not cancel it. Concrete subclasses
 * cancel it with a bare {@code @JsonSerialize}; {@code BaseAttribute} and abstract intermediates such as
 * {@code MetadataAttribute} do not, and write a different key set.</li>
 * </ul>
 * {@code BaseAttributeV2}'s {@code @JsonSubTypes} registrations are vestigial: none of the named classes extend it, so
 * reading through that type fails with an unresolvable type id.
 *
 * <h2>When a golden fails</h2> During the migration a diff is a finding to explain, not a test to update. Trace it to a
 * documented Jackson 3 behaviour change before regenerating with {@code -Dgolden.regenerate=true}, and review the
 * regenerated diff in the PR. Outside the migration it means an ordinary change altered a wire or column shape.
 *
 * <h2>Mapper parity</h2> Each golden is produced by the writer serving its surface, via {@code GoldenMappers}. The
 * platform has three and they disagree, so the wrong one baselines a shape production never emits: {@code jsonb}
 * columns go through Hibernate's own mapper, which {@code JsonColumnFormatMapperConfig} states as
 * {@code ObjectMapperFactory.jsonColumn()}.
 *
 * <p>
 * These are plain JUnit 5 tests with no application context, so they add nothing to {@code ContextSignatureGuardTest}.
 * Keep it that way.
 */
package com.otilm.core.serialization.golden;

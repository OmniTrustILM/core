package com.otilm.core.events.handlers.discovery;

import com.otilm.api.exception.ValidationException;
import java.security.cert.CertificateException;
import java.sql.SQLException;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.transaction.UnexpectedRollbackException;

import static org.assertj.core.api.Assertions.assertThat;

class DiscoveryFailureReasonTest {

    /**
     * Classified, not forwarded. Reachable throw sites concatenate entity data into their message -- a key upload
     * failure embeds the key material -- and nothing about the type separates those from the harmless ones.
     */
    @Test
    void classifiesAValidationFailureRatherThanForwardingItsMessage() {
        assertThat(DiscoveryFailureReason
                .shape(new ValidationException("Failed to calculate fingerprint from key content: MIIBIjANBgkq")))
                .as("no entity data may reach an API-exposed field")
                .isEqualTo("the certificate did not pass validation");
    }

    @Test
    void classifiesACertificateExceptionRatherThanForwardingProviderText() {
        assertThat(DiscoveryFailureReason.shape(new CertificateException("unsupported signature algorithm")))
                .as("parser messages come from the JDK and BouncyCastle, not the platform")
                .isEqualTo("the discovered certificate could not be parsed");
    }

    @Test
    void classifiesAWrappedDataIntegrityViolationWithoutLeakingTheWrappersText() {
        String reason = DiscoveryFailureReason
                .shape(new IllegalStateException(
                        "could not execute statement [insert into core.certificate (uuid,fingerprint) ...]",
                        new DataIntegrityViolationException("duplicate key value violates unique constraint",
                                uniqueViolation("certificate_fingerprint_key"))));

        assertThat(reason)
                .isEqualTo("a concurrent import committed the same certificate")
                .doesNotContain("insert into")
                .doesNotContain("core.certificate");
    }

    @Test
    void separatesADuplicateFromAnyOtherIntegrityViolation() {
        assertThat(DiscoveryFailureReason
                .shape(new DataIntegrityViolationException("violates foreign key constraint",
                        constraintViolation(ConstraintViolationException.ConstraintKind.OTHER,
                                "certificate_owner_fk"))))
                .as("a foreign-key or check violation is a different defect and must not read as a benign race")
                .isEqualTo("a database constraint rejected the certificate");
    }

    @Test
    void passesThroughAnAlreadyShapedRollbackReason() {
        String reason = DiscoveryFailureReason
                .shape(new DiscoveryImportRollbackException(
                        "trigger evaluation failed: the discovered certificate could not be parsed",
                        new DataIntegrityViolationException("insert into core.certificate ...")));

        assertThat(reason)
                .as("re-deriving from the cause would replace the specific reason with generic text")
                .isEqualTo("trigger evaluation failed: the discovered certificate could not be parsed");
    }

    @Test
    void survivesACyclicCauseChain() {
        RuntimeException outer = new RuntimeException("outer");
        RuntimeException inner = new RuntimeException("inner", outer);
        outer.initCause(inner);

        assertThat(DiscoveryFailureReason.shape(outer)).isEqualTo("an unexpected error occurred");
    }

    @Test
    void classifiesADataIntegrityViolationWithoutLeakingSql() {
        String reason = DiscoveryFailureReason
                .shape(new DataIntegrityViolationException(
                        "could not execute statement [ERROR: duplicate key value violates unique constraint "
                                + "\"certificate_fingerprint_key\"] [insert into core.certificate (uuid,fingerprint) ...]",
                        uniqueViolation("certificate_fingerprint_key")));

        assertThat(reason)
                .isEqualTo("a concurrent import committed the same certificate")
                .doesNotContain("insert into")
                .doesNotContain("certificate_fingerprint_key");
    }

    /**
     * Without a Hibernate constraint violation in the chain the kind is unknowable, so the reason has to stay at the
     * weaker claim rather than assert a race that may not have happened.
     */
    @Test
    void doesNotClaimARaceWhenTheConstraintKindIsUnknown() {
        assertThat(DiscoveryFailureReason.shape(new DataIntegrityViolationException("could not execute statement")))
                .isEqualTo("a database constraint rejected the certificate");
    }

    /**
     * The signals a native insert actually produces. Hibernate's own constraint kind is absent there, so relying on it
     * alone reported a genuine duplicate as an unspecified constraint failure.
     */
    @Test
    void recognisesADuplicateFromTheSqlStateAlone() {
        SQLException uniqueViolation = new SQLException("ERROR: duplicate key value violates unique constraint",
                "23505");

        assertThat(DiscoveryFailureReason
                .shape(new DataIntegrityViolationException("could not execute statement", uniqueViolation)))
                .isEqualTo("a concurrent import committed the same certificate");
    }

    @Test
    void recognisesADuplicateFromSpringsOwnTranslation() {
        assertThat(DiscoveryFailureReason
                .shape(new DuplicateKeyException("duplicate key value violates unique constraint")))
                .isEqualTo("a concurrent import committed the same certificate");
    }

    @Test
    void doesNotTreatAnotherIntegrityStateAsADuplicate() {
        SQLException foreignKeyViolation = new SQLException("ERROR: violates foreign key constraint", "23503");

        assertThat(DiscoveryFailureReason
                .shape(new DataIntegrityViolationException("could not execute statement", foreignKeyViolation)))
                .isEqualTo("a database constraint rejected the certificate");
    }

    private static ConstraintViolationException uniqueViolation(String constraintName) {
        return constraintViolation(ConstraintViolationException.ConstraintKind.UNIQUE, constraintName);
    }

    private static ConstraintViolationException constraintViolation(ConstraintViolationException.ConstraintKind kind,
            String constraintName) {
        return new ConstraintViolationException("could not execute statement",
                new SQLException("ERROR: violates constraint \"%s\"".formatted(constraintName)), kind, constraintName);
    }

    @Test
    void classifiesAnUnexpectedRollbackWithoutLeakingInternals() {
        assertThat(DiscoveryFailureReason
                .shape(new UnexpectedRollbackException(
                        "Transaction silently rolled back because it has been marked as rollback-only")))
                .isEqualTo("the import transaction was rolled back");
    }

    /**
     * Same exception, different transaction: after the import has committed, only the trigger's own can have rolled
     * back, and naming the import's would send the operator looking at the wrong thing.
     */
    @Test
    void namesTheTriggerTransactionWhenTheImportHasAlreadyCommitted() {
        assertThat(DiscoveryFailureReason
                .shapeTriggerFailure(new UnexpectedRollbackException(
                        "Transaction silently rolled back because it has been marked as rollback-only")))
                .isEqualTo("the trigger's transaction was rolled back");
    }

    /** The scope only changes the rollback wording; every other classification is shared. */
    @Test
    void classifiesEverythingElseTheSameWayForATriggerFailure() {
        assertThat(DiscoveryFailureReason.shapeTriggerFailure(new CertificateException("bad signature")))
                .isEqualTo("the discovered certificate could not be parsed");
        assertThat(
                DiscoveryFailureReason.shapeTriggerFailure(new IllegalStateException("core.cert_content.id is null")))
                .isEqualTo("an unexpected error occurred");
    }

    @Test
    void classifiesAnythingElseGenerically() {
        assertThat(DiscoveryFailureReason.shape(new IllegalStateException("core.certificate_content.id is null")))
                .isEqualTo("an unexpected error occurred");
    }

    @Test
    void neverEchoesAStringifiedNullMessage() {
        assertThat(DiscoveryFailureReason.shape(new ValidationException((String) null)))
                .isEqualTo("the certificate did not pass validation");
    }
}

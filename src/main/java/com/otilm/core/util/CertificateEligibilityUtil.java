package com.otilm.core.util;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.oid.SystemOid;
import com.otilm.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.Certificate_;
import com.czertainly.core.dao.entity.CryptographicKey_;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.czertainly.core.dao.entity.CryptographicKeyItem_;
import com.otilm.core.model.crypto.CryptographicKeyItemModel;
import com.otilm.core.model.signing.SigningCertificate;
import jakarta.annotation.Nullable;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Subquery;
import org.apache.commons.lang3.function.TriFunction;

import java.util.ArrayList;
import java.util.List;

/**
 * Eligibility (acceptability) rules that decide whether a {@link Certificate} may serve a given protocol role:
 * SCEP CA certificate, CMP signing certificate, or digital-signing certificate.
 *
 * <p>Each role is exposed in two equivalent forms:
 * <ul>
 *     <li>an in-memory {@code isCertificate…Acceptable} predicate evaluating a single loaded entity (or cached snapshot), and</li>
 *     <li>a {@code constructQuery…Acceptable} JPA Criteria builder that pushes the same rule into a database query.</li>
 * </ul>
 * The two forms must stay behaviourally equivalent.
 */
public class CertificateEligibilityUtil {

    private CertificateEligibilityUtil() {
    }

    public static boolean isCertificateScepCaCertAcceptable(Certificate certificate, boolean intuneEnabled) {
        if (certificate.isArchived() || certificate.getKey() == null || !certificate.getState().equals(CertificateState.ISSUED) || (!certificate.getValidationStatus().equals(CertificateValidationStatus.VALID) && !certificate.getValidationStatus().equals(CertificateValidationStatus.EXPIRING))) {
            return false;
        }

        // Check if the public key has usage ENCRYPT enabled and private key has DECRYPT and SIGN enabled
        // It is required to check RSA for public key since only RSA keys are encryption capable
        // Other types of keys such as split keys and secret keys are not needed to be checked since they cannot be used in certificates
        boolean privateKeyAvailable = false;
        for (CryptographicKeyItem item : certificate.getKey().getItems()) {
            if ((intuneEnabled && !item.getKeyAlgorithm().equals(KeyAlgorithm.RSA))
                    || (!intuneEnabled && !item.getKeyAlgorithm().equals(KeyAlgorithm.RSA) && !item.getKeyAlgorithm().equals(KeyAlgorithm.ECDSA))) {
                return false;
            } else if (item.getKeyAlgorithm().equals(KeyAlgorithm.RSA) && item.getType().equals(KeyType.PUBLIC_KEY)) {
                if (!item.getUsage().containsAll(List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY))) {
                    return false;
                }
            } else if (item.getKeyAlgorithm().equals(KeyAlgorithm.RSA) && item.getType().equals(KeyType.PRIVATE_KEY)) {
                if (item.getState() != KeyState.ACTIVE || !item.getUsage().containsAll(List.of(KeyUsage.DECRYPT, KeyUsage.SIGN))) {
                    return false;
                }
                privateKeyAvailable = true;
            } else if (item.getKeyAlgorithm().equals(KeyAlgorithm.ECDSA) && item.getType().equals(KeyType.PUBLIC_KEY)) {
                if (!item.getUsage().containsAll(List.of(KeyUsage.VERIFY))) {
                    return false;
                }
            } else if (item.getKeyAlgorithm().equals(KeyAlgorithm.ECDSA) && item.getType().equals(KeyType.PRIVATE_KEY)) {
                if (item.getState() != KeyState.ACTIVE || !item.getUsage().containsAll(List.of(KeyUsage.SIGN))) {
                    return false;
                }
                privateKeyAvailable = true;
            }
        }
        return privateKeyAvailable;
    }

    /*
     * Constructed Query Graph for SCEP CA Certificate Filtering:
     *
     * Certificate (root)
     * |-- NOT archived
     * |-- state == ISSUED
     * |-- validationStatus IN (VALID, EXPIRING)
     * |-- keyUuid IS NOT NULL
     * |-- ALL items must have valid algorithm (RSA [and ECDSA if intuneEnabled=false])
     * |   |-- Subquery invalidAlgoSubquery: NOT EXISTS item with invalid algorithm
     * |-- AT LEAST ONE valid private key must exist
     * |   |-- Subquery privateKeySubquery: EXISTS private key meeting criteria
     * |-- ALL private keys must meet criteria
     * |   |-- Subquery invalidPrivateKeySubquery: NOT EXISTS private key NOT meeting criteria
     * |       |-- RSA Private AND state=ACTIVE AND usage & (DECRYPT | SIGN) == (DECRYPT | SIGN)
     * |       OR
     * |       |-- ECDSA Private AND state=ACTIVE AND usage & SIGN [only if intuneEnabled=false]
     * |-- AT LEAST ONE valid public key must exist
     * |   |-- Subquery publicKeySubquery: EXISTS public key meeting criteria
     * |-- ALL public keys must meet criteria
     *     |-- Subquery invalidPublicKeySubquery: NOT EXISTS public key NOT meeting criteria
     *         |-- RSA Public AND usage & (ENCRYPT | VERIFY) == (ENCRYPT | VERIFY)
     *         OR
     *         |-- ECDSA Public AND usage & VERIFY [only if intuneEnabled=false]
     */
    public static TriFunction<Root<Certificate>, CriteriaBuilder, CriteriaQuery<?>, Predicate> constructQueryScepCaCertAcceptable(boolean intuneEnabled) {
        return (root, cb, cr) -> {
            // Valid key algorithms based on intuneEnabled
            List<KeyAlgorithm> validAlgorithms = intuneEnabled ? List.of(KeyAlgorithm.RSA) : List.of(KeyAlgorithm.RSA, KeyAlgorithm.ECDSA);

            // Subquery to ensure ALL key items have a valid algorithm.
            Subquery<Integer> invalidAlgoSubquery = cr.subquery(Integer.class);
            Root<CryptographicKeyItem> subRoot = invalidAlgoSubquery.from(CryptographicKeyItem.class);
            invalidAlgoSubquery.select(cb.literal(1));
            invalidAlgoSubquery.where(
                    cb.equal(subRoot.get(CryptographicKeyItem_.KEY_UUID), root.get(Certificate_.KEY_UUID)),
                    cb.not(subRoot.get(CryptographicKeyItem_.KEY_ALGORITHM).in(validAlgorithms))
            );

            // Subquery to ensure at least one private key meeting criteria is available.
            Subquery<Integer> privateKeySubquery = cr.subquery(Integer.class);
            Root<CryptographicKeyItem> pkSubRoot = privateKeySubquery.from(CryptographicKeyItem.class);
            privateKeySubquery.select(cb.literal(1));
            privateKeySubquery.where(
                    cb.equal(pkSubRoot.get(CryptographicKeyItem_.KEY_UUID), root.get(Certificate_.KEY_UUID)),
                    cb.equal(pkSubRoot.get(CryptographicKeyItem_.TYPE), KeyType.PRIVATE_KEY),
                    constructPrivateKeyItemValidPredicate(cb, pkSubRoot, intuneEnabled)
            );

            // Subquery to check if there are any private keys that DO NOT meet criteria.
            Subquery<Integer> invalidPrivateKeySubquery = cr.subquery(Integer.class);
            Root<CryptographicKeyItem> invPkSubRoot = invalidPrivateKeySubquery.from(CryptographicKeyItem.class);
            invalidPrivateKeySubquery.select(cb.literal(1));
            invalidPrivateKeySubquery.where(
                    cb.equal(invPkSubRoot.get(CryptographicKeyItem_.KEY_UUID), root.get(Certificate_.KEY_UUID)),
                    cb.equal(invPkSubRoot.get(CryptographicKeyItem_.TYPE), KeyType.PRIVATE_KEY),
                    cb.not(constructPrivateKeyItemValidPredicate(cb, invPkSubRoot, intuneEnabled))
            );

            // Subquery to ensure at least one public key meeting criteria is available.
            Subquery<Integer> publicKeySubquery = cr.subquery(Integer.class);
            Root<CryptographicKeyItem> pubSubRoot = publicKeySubquery.from(CryptographicKeyItem.class);
            publicKeySubquery.select(cb.literal(1));
            publicKeySubquery.where(
                    cb.equal(pubSubRoot.get(CryptographicKeyItem_.KEY_UUID), root.get(Certificate_.KEY_UUID)),
                    cb.equal(pubSubRoot.get(CryptographicKeyItem_.TYPE), KeyType.PUBLIC_KEY),
                    constructPublicKeyItemValidPredicate(cb, pubSubRoot, intuneEnabled)
            );

            // Subquery to check if there are any public keys that DO NOT meet criteria.
            Subquery<Integer> invalidPublicKeySubquery = cr.subquery(Integer.class);
            Root<CryptographicKeyItem> invPubSubRoot = invalidPublicKeySubquery.from(CryptographicKeyItem.class);
            invalidPublicKeySubquery.select(cb.literal(1));
            invalidPublicKeySubquery.where(
                    cb.equal(invPubSubRoot.get(CryptographicKeyItem_.KEY_UUID), root.get(Certificate_.KEY_UUID)),
                    cb.equal(invPubSubRoot.get(CryptographicKeyItem_.TYPE), KeyType.PUBLIC_KEY),
                    cb.not(constructPublicKeyItemValidPredicate(cb, invPubSubRoot, intuneEnabled))
            );

            return cb.and(
                    cb.not(root.get(Certificate_.ARCHIVED)),
                    cb.isNotNull(root.get(Certificate_.KEY_UUID)),
                    cb.equal(root.get(Certificate_.STATE), CertificateState.ISSUED),
                    root.get(Certificate_.VALIDATION_STATUS).in(List.of(CertificateValidationStatus.VALID, CertificateValidationStatus.EXPIRING)),
                    cb.not(cb.exists(invalidAlgoSubquery)),
                    cb.exists(privateKeySubquery),
                    cb.not(cb.exists(invalidPrivateKeySubquery)),
                    cb.exists(publicKeySubquery),
                    cb.not(cb.exists(invalidPublicKeySubquery))
            );
        };
    }

    private static Predicate constructKeyItemPredicate(CriteriaBuilder cb, Path<CryptographicKeyItem> itemPath, @Nullable KeyAlgorithm algorithm,
                                                       @Nullable KeyState state, int usageMask) {
        List<Predicate> predicates = new ArrayList<>();
        if (algorithm != null) predicates.add(cb.equal(itemPath.get(CryptographicKeyItem_.KEY_ALGORITHM), algorithm));
        if (state != null) predicates.add(cb.equal(itemPath.get(CryptographicKeyItem_.STATE), state));
        predicates.add(cb.equal(cb.function(PostgresFunctionContributor.BIT_AND_FUNCTION, Integer.class,
                itemPath.get(CryptographicKeyItem_.USAGE), cb.literal(usageMask)), usageMask));
        return cb.and(predicates.toArray(new Predicate[0]));
    }

    private static Predicate constructPrivateKeyItemValidPredicate(CriteriaBuilder cb, Path<CryptographicKeyItem> itemPath, boolean intuneEnabled) {
        return intuneEnabled ? constructKeyItemPredicate(cb, itemPath, KeyAlgorithm.RSA, KeyState.ACTIVE, KeyUsage.DECRYPT.getBit() | KeyUsage.SIGN.getBit()) :
                cb.or(constructKeyItemPredicate(cb, itemPath, KeyAlgorithm.RSA, KeyState.ACTIVE, KeyUsage.DECRYPT.getBit() | KeyUsage.SIGN.getBit()),
                        constructKeyItemPredicate(cb, itemPath, KeyAlgorithm.ECDSA, KeyState.ACTIVE, KeyUsage.SIGN.getBit()));
    }

    private static Predicate constructPublicKeyItemValidPredicate(CriteriaBuilder cb, Path<CryptographicKeyItem> itemPath, boolean intuneEnabled) {
        return intuneEnabled ? constructKeyItemPredicate(cb, itemPath, KeyAlgorithm.RSA, null, KeyUsage.ENCRYPT.getBit() | KeyUsage.VERIFY.getBit()) :
                cb.or(constructKeyItemPredicate(cb, itemPath, KeyAlgorithm.RSA, null, KeyUsage.ENCRYPT.getBit() | KeyUsage.VERIFY.getBit()),
                        constructKeyItemPredicate(cb, itemPath, KeyAlgorithm.ECDSA, null, KeyUsage.VERIFY.getBit()));
    }

    /*
     * Constructed Query Graph for CMP Signing Certificate Filtering:
     *
     * Certificate (root)
     * |-- NOT archived
     * |-- keyUuid IS NOT NULL
     * |-- state == ISSUED
     * |-- validationStatus IN (VALID, EXPIRING)
     * |-- AT LEAST ONE private key must exist
     * |-- ALL private keys must meet criteria
     *     |-- state=ACTIVE AND usage & SIGN
     */
    public static TriFunction<Root<Certificate>, CriteriaBuilder, CriteriaQuery<?>, Predicate> constructQueryCmpSigningCertAcceptable() {
        return (root, cb, cr) -> {
            // Subquery to ensure at least one private key exists.
            Subquery<Integer> privateKeySubquery = cr.subquery(Integer.class);
            Root<CryptographicKeyItem> pkSubRoot = privateKeySubquery.from(CryptographicKeyItem.class);
            privateKeySubquery.select(cb.literal(1));
            privateKeySubquery.where(
                    cb.equal(pkSubRoot.get(CryptographicKeyItem_.KEY_UUID), root.get(Certificate_.KEY_UUID)),
                    cb.equal(pkSubRoot.get(CryptographicKeyItem_.TYPE), KeyType.PRIVATE_KEY)
            );

            // Subquery to check if there are any private keys that DO NOT meet criteria.
            Subquery<Integer> invalidPrivateKeySubquery = cr.subquery(Integer.class);
            Root<CryptographicKeyItem> invPkSubRoot = invalidPrivateKeySubquery.from(CryptographicKeyItem.class);
            invalidPrivateKeySubquery.select(cb.literal(1));
            invalidPrivateKeySubquery.where(
                    cb.equal(invPkSubRoot.get(CryptographicKeyItem_.KEY_UUID), root.get(Certificate_.KEY_UUID)),
                    cb.equal(invPkSubRoot.get(CryptographicKeyItem_.TYPE), KeyType.PRIVATE_KEY),
                    cb.not(constructKeyItemPredicate(cb, invPkSubRoot, null, KeyState.ACTIVE, KeyUsage.SIGN.getBit()))
            );

            return cb.and(
                    cb.not(root.get(Certificate_.ARCHIVED)),
                    cb.isNotNull(root.get(Certificate_.KEY_UUID)),
                    cb.equal(root.get(Certificate_.STATE), CertificateState.ISSUED),
                    root.get(Certificate_.VALIDATION_STATUS).in(List.of(CertificateValidationStatus.VALID, CertificateValidationStatus.EXPIRING)),
                    cb.exists(privateKeySubquery),
                    cb.not(cb.exists(invalidPrivateKeySubquery))
            );
        };
    }

    public static boolean isCertificateCmpAcceptable(Certificate certificate) {
        if (certificate.isArchived()) return false;
        if (certificate.getKey() == null ||
                !certificate.getState().equals(CertificateState.ISSUED) ||
                (!certificate.getValidationStatus().equals(CertificateValidationStatus.VALID)
                        && !certificate.getValidationStatus().equals(CertificateValidationStatus.EXPIRING))
        ) {
            return false;
        }

        // Check if the private key has SIGN enabled
        // Other types of keys such as split keys and secret keys are not needed to be checked since they cannot be used in certificates
        boolean privateKeyAvailable = false;
        for (CryptographicKeyItem item : certificate.getKey().getItems()) {
            if (item.getType().equals(KeyType.PRIVATE_KEY)) {
                if (item.getState() != KeyState.ACTIVE || !item.getUsage().contains(KeyUsage.SIGN)) {
                    return false;
                }
                privateKeyAvailable = true;
            }
        }
        return privateKeyAvailable;
    }

    /*
     * Constructed Query Graph for Digital Signing Certificate Filtering:
     *
     * Certificate (root)
     * |-- NOT archived
     * |-- keyUuid IS NOT NULL
     * |-- state == ISSUED
     * |-- validationStatus IN (VALID, EXPIRING)
     * |-- key.tokenProfileUuid IS NOT NULL           (associated Token Profile)
     * |-- key.tokenInstanceReferenceUuid IS NOT NULL (associated Token Instance)
     * |-- AT LEAST ONE private key must exist
     * |-- ALL private keys must meet criteria
     *     |-- state=ACTIVE AND usage & SIGN
     * |-- AT LEAST ONE public key must exist
     * |-- (TIMESTAMPING only) extendedKeyUsage is exclusively the TSA OID (RFC 3161)
     * |-- (TIMESTAMPING only) extendedKeyUsageCritical is true (RFC 3161)
     * |-- (TIMESTAMPING + qualifiedTimestamp only) certificate carries id-etsi-qcs-QcCompliance (ETSI EN 319 412-5 / EN 319 421)
     */
    public static TriFunction<Root<Certificate>, CriteriaBuilder, CriteriaQuery<?>, Predicate> constructQueryDigitalSigningCertAcceptable(SigningWorkflowType workflowType, boolean qualifiedTimestamp) {
        return (root, cb, cr) -> {
            // Subquery to ensure at least one private key exists.
            Subquery<Integer> privateKeySubquery = cr.subquery(Integer.class);
            Root<CryptographicKeyItem> pkSubRoot = privateKeySubquery.from(CryptographicKeyItem.class);
            privateKeySubquery.select(cb.literal(1));
            privateKeySubquery.where(
                    cb.equal(pkSubRoot.get(CryptographicKeyItem_.KEY_UUID), root.get(Certificate_.KEY_UUID)),
                    cb.equal(pkSubRoot.get(CryptographicKeyItem_.TYPE), KeyType.PRIVATE_KEY)
            );

            // Subquery to check if there are any private keys that DO NOT meet criteria.
            Subquery<Integer> invalidPrivateKeySubquery = cr.subquery(Integer.class);
            Root<CryptographicKeyItem> invPkSubRoot = invalidPrivateKeySubquery.from(CryptographicKeyItem.class);
            invalidPrivateKeySubquery.select(cb.literal(1));
            invalidPrivateKeySubquery.where(
                    cb.equal(invPkSubRoot.get(CryptographicKeyItem_.KEY_UUID), root.get(Certificate_.KEY_UUID)),
                    cb.equal(invPkSubRoot.get(CryptographicKeyItem_.TYPE), KeyType.PRIVATE_KEY),
                    cb.not(constructKeyItemPredicate(cb, invPkSubRoot, null, KeyState.ACTIVE, KeyUsage.SIGN.getBit()))
            );

            // Subquery to ensure at least one public key exists.
            Subquery<Integer> publicKeySubquery = cr.subquery(Integer.class);
            Root<CryptographicKeyItem> pubSubRoot = publicKeySubquery.from(CryptographicKeyItem.class);
            publicKeySubquery.select(cb.literal(1));
            publicKeySubquery.where(
                    cb.equal(pubSubRoot.get(CryptographicKeyItem_.KEY_UUID), root.get(Certificate_.KEY_UUID)),
                    cb.equal(pubSubRoot.get(CryptographicKeyItem_.TYPE), KeyType.PUBLIC_KEY)
            );

            List<Predicate> predicates = new ArrayList<>();
            predicates.add(cb.not(root.get(Certificate_.ARCHIVED)));
            predicates.add(cb.isNotNull(root.get(Certificate_.KEY_UUID)));
            predicates.add(cb.equal(root.get(Certificate_.STATE), CertificateState.ISSUED));
            predicates.add(root.get(Certificate_.VALIDATION_STATUS).in(List.of(CertificateValidationStatus.VALID, CertificateValidationStatus.EXPIRING)));
            predicates.add(cb.exists(privateKeySubquery));
            predicates.add(cb.not(cb.exists(invalidPrivateKeySubquery)));
            predicates.add(cb.exists(publicKeySubquery));
            predicates.add(cb.isNotNull(root.get(Certificate_.KEY).get(CryptographicKey_.TOKEN_PROFILE_UUID)));
            predicates.add(cb.isNotNull(root.get(Certificate_.KEY).get(CryptographicKey_.TOKEN_INSTANCE_REFERENCE_UUID)));

            // RFC 3161: the EKU extension MUST contain only id-kp-timeStamping and MUST be critical.
            if (workflowType == SigningWorkflowType.TIMESTAMPING) {
                String exclusiveTsaEku = MetaDefinitions.serializeArrayString(List.of(SystemOid.TIME_STAMPING.getOid()));
                predicates.add(cb.equal(root.get(Certificate_.EXTENDED_KEY_USAGE), exclusiveTsaEku));
                predicates.add(cb.isTrue(root.get(Certificate_.EXTENDED_KEY_USAGE_CRITICAL)));
                // ETSI EN 319 421 §6.2: for a qualified TSA the signer certificate MUST carry the
                // id-etsi-qcs-QcCompliance statement (OID 0.4.0.1862.1.1, ETSI EN 319 412-5).
                if (qualifiedTimestamp) {
                    predicates.add(cb.isTrue(root.get(Certificate_.QC_COMPLIANCE)));
                }
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    /**
     * Determines whether a {@link Certificate} entity is acceptable for digital signing under the given workflow type and qualification level.
     *
     * <p>For {@link SigningWorkflowType#TIMESTAMPING}, RFC 3161 requirements are enforced (exclusive, critical extended key usage EKU).
     * When {@code qualifiedTimestamp} is {@code true}, the certificate is additionally required to carry the
     * {@code id-etsi-qcs-QcCompliance} statement (OID {@code 0.4.0.1862.1.1}) as mandated by ETSI EN 319 421 §6.2
     * and defined in ETSI EN 319 412-5.
     *
     * @param certificate        the entity to evaluate
     * @param workflowType       the signing workflow
     * @param qualifiedTimestamp when {@code true} and workflow is TIMESTAMPING, also requires id-etsi-qcs-QcCompliance in QCStatements
     * @return {@code true} iff all applicable requirements are satisfied
     */
    public static boolean isCertificateDigitalSigningAcceptable(Certificate certificate, SigningWorkflowType workflowType, boolean qualifiedTimestamp) {
        List<SigningPrivateKeyView> privateKeys = new ArrayList<>();
        boolean hasPublicKey = false;
        if (certificate.getKey() != null) {
            for (CryptographicKeyItem item : certificate.getKey().getItems()) {
                if (item.getType() == KeyType.PRIVATE_KEY) {
                    privateKeys.add(new SigningPrivateKeyView(item.getState(), item.getUsage()));
                } else if (item.getType() == KeyType.PUBLIC_KEY) {
                    hasPublicKey = true;
                }
            }
        }
        SigningAcceptabilityView view = new SigningAcceptabilityView(
                certificate.isArchived(),
                certificate.getKey() != null,
                certificate.getKey() != null && certificate.getKey().getTokenProfile() != null,
                certificate.getKey() != null && certificate.getKey().getTokenInstanceReference() != null,
                certificate.getState(),
                certificate.getValidationStatus(),
                privateKeys,
                hasPublicKey,
                MetaDefinitions.deserializeArrayString(certificate.getExtendedKeyUsage()),
                Boolean.TRUE.equals(certificate.getExtendedKeyUsageCritical()),
                Boolean.TRUE.equals(certificate.getQcCompliance())
        );
        return isCertificateDigitalSigningAcceptable(view, workflowType, qualifiedTimestamp);
    }

    /**
     * Cache-backed counterpart of {@link #isCertificateDigitalSigningAcceptable(Certificate, SigningWorkflowType, boolean)}.
     * Evaluates the same acceptability rules against the {@link SigningCertificate} snapshot and its
     * {@link CryptographicKeyItemModel} key items instead of the JPA entity graph.
     *
     * @param certificate        the cached certificate snapshot
     * @param keyItems           the cached key-item snapshots for the certificate's key
     * @param workflowType       the signing workflow
     * @param qualifiedTimestamp when {@code true} and workflow is TIMESTAMPING, also requires id-etsi-qcs-QcCompliance
     * @return {@code true} iff all applicable requirements are satisfied
     */
    public static boolean isCertificateDigitalSigningAcceptable(SigningCertificate certificate, List<CryptographicKeyItemModel> keyItems,
                                                                SigningWorkflowType workflowType, boolean qualifiedTimestamp) {
        List<SigningPrivateKeyView> privateKeys = new ArrayList<>();
        boolean hasPublicKey = false;
        for (CryptographicKeyItemModel item : keyItems) {
            if (item.keyType() == KeyType.PRIVATE_KEY) {
                privateKeys.add(new SigningPrivateKeyView(item.keyState(), item.keyUsage()));
            } else if (item.keyType() == KeyType.PUBLIC_KEY) {
                hasPublicKey = true;
            }
        }
        SigningAcceptabilityView view = new SigningAcceptabilityView(
                certificate.archived(),
                certificate.keyUuid() != null,
                certificate.tokenProfileUuid() != null,
                certificate.tokenInstanceReferenceUuid() != null,
                certificate.state(),
                certificate.validationStatus(),
                privateKeys,
                hasPublicKey,
                certificate.extendedKeyUsageOids(),
                Boolean.TRUE.equals(certificate.extendedKeyUsageCritical()),
                Boolean.TRUE.equals(certificate.qcCompliance())
        );
        return isCertificateDigitalSigningAcceptable(view, workflowType, qualifiedTimestamp);
    }

    /**
     * Inputs the digital-signing acceptability rule reads, decoupled from the backing data source (JPA entity graph
     * vs cached {@link SigningCertificate} snapshot).
     */
    private record SigningAcceptabilityView(
            boolean archived,
            boolean hasKey,
            boolean hasTokenProfile,
            boolean hasTokenInstanceReference,
            CertificateState state,
            CertificateValidationStatus validationStatus,
            List<SigningPrivateKeyView> privateKeys,
            boolean hasPublicKey,
            List<String> extendedKeyUsageOids,
            boolean extendedKeyUsageCritical,
            boolean qcCompliant
    ) {}

    private record SigningPrivateKeyView(KeyState state, List<KeyUsage> usage) {}

    private static boolean isCertificateDigitalSigningAcceptable(SigningAcceptabilityView view, SigningWorkflowType workflowType, boolean qualifiedTimestamp) {
        if (view.archived()) return false;
        if (!view.hasKey()
                || view.state() != CertificateState.ISSUED
                || (view.validationStatus() != CertificateValidationStatus.VALID
                        && view.validationStatus() != CertificateValidationStatus.EXPIRING)
        ) {
            return false;
        }

        // The associated CryptographicKey must have a Token Profile and Token Instance Reference assigned.
        if (!view.hasTokenProfile()) return false;
        if (!view.hasTokenInstanceReference()) return false;

        // All private keys must be ACTIVE and carry the SIGN usage.
        // Other key types (split keys, secret keys) do not apply to certificate signing.
        if (view.privateKeys().isEmpty()) return false;
        for (SigningPrivateKeyView key : view.privateKeys()) {
            if (key.state() != KeyState.ACTIVE || !key.usage().contains(KeyUsage.SIGN)) {
                return false;
            }
        }

        // A public key item must be present; the signer creator requires it to resolve the signing algorithm.
        if (!view.hasPublicKey()) return false;

        if (workflowType == SigningWorkflowType.TIMESTAMPING) {
            // RFC 3161: the EKU extension MUST contain only id-kp-timeStamping and MUST be critical.
            List<String> ekuOids = view.extendedKeyUsageOids();
            boolean ekuCompliant = ekuOids.size() == 1
                    && ekuOids.contains(SystemOid.TIME_STAMPING.getOid())
                    && view.extendedKeyUsageCritical();
            if (!ekuCompliant) return false;

            // ETSI EN 319 421 §6.2: for a qualified TSA the signer certificate MUST carry the
            // id-etsi-qcs-QcCompliance statement (OID 0.4.0.1862.1.1, ETSI EN 319 412-5).
            return !qualifiedTimestamp || view.qcCompliant();
        }

        return true;
    }
}

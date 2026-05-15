package com.czertainly.core.util;

import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.cryptography.key.KeyState;
import com.czertainly.api.model.core.cryptography.key.KeyUsage;
import com.czertainly.api.model.core.oid.SystemOid;
import org.junit.jupiter.params.provider.Arguments;

import java.util.List;
import java.util.stream.Stream;

public class CertificateTestData {

    public record KeyItemData(
            KeyType type,
            KeyAlgorithm algorithm,
            List<KeyUsage> usage,
            KeyState state
    ) {
    }

    public static Stream<Arguments> provideCmpAcceptableTestData() {
        return Stream.of(
                // 1. Certificate that should be accepted (RSA)
                Arguments.of("RSA Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true),

                // 2. Certificate that should be accepted (ECDSA)
                Arguments.of("ECDSA Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true),

                // 3. Certificate that should be accepted (EXPIRING)
                Arguments.of("Expiring Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.EXPIRING, false,
                        true),

                // 4. Certificate with no key (should be ignored)
                Arguments.of("No Key Cert",
                        List.of(),
                        List.of(),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false),

                // 5. Archived certificate (should be ignored)
                Arguments.of("Archived Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, true,
                        false),

                // 6. Certificate with wrong state (should be ignored)
                Arguments.of("Wrong State Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.PENDING_APPROVAL, CertificateValidationStatus.VALID, false,
                        false),

                // 7. Certificate with wrong validation status (should be ignored)
                Arguments.of("Invalid Status Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.REVOKED, false,
                        false),

                // 8. Certificate with no private key (should be ignored)
                Arguments.of("No Private Key Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false),

                // 9. Certificate with inactive private key (should be ignored)
                Arguments.of("Inactive Private Key Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.DEACTIVATED)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false),

                // 10. Certificate with private key missing SIGN usage (should be ignored)
                Arguments.of("No Sign Usage Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.DECRYPT), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false),

                // 11. Certificate with a Falcon key (should be accepted)
                Arguments.of("Falcon Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.FALCON, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.FALCON, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true),

                // 12. Public key only (should be rejected)
                Arguments.of("Public Key Only",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false),

                // 13. Multiple private keys, all valid (should be accepted)
                Arguments.of("Multiple Valid Private Keys",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(
                                new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE),
                                new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)
                        ),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true),

                // 14. Multiple private keys, one invalid state (should be rejected)
                Arguments.of("Multiple Private Keys, One Inactive",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(
                                new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE),
                                new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.DEACTIVATED)
                        ),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false),

                // 15. Multiple private keys, one missing SIGN usage (should be rejected)
                Arguments.of("Multiple Private Keys, One Missing Sign",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(
                                new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE),
                                new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.DECRYPT), KeyState.ACTIVE)
                        ),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false),

                // 16. Multiple public keys, one private key (should be accepted)
                Arguments.of("Multiple Public Keys",
                        List.of(
                                new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE),
                                new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)
                        ),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true)
        );
    }

    public static Stream<Arguments> provideScepCaCertificateTestData() {
        return Stream.of(
                // 1. Certificate that should be accepted (RSA)
                Arguments.of("RSA Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.DECRYPT, KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, true),

                // 2. Certificate that should be accepted (ECDSA)
                Arguments.of("ECDSA Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, true),

                // 3. Certificate with no key (should be ignored)
                Arguments.of("No Key Cert",
                        List.of(),
                        List.of(),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, false),

                // 4. Archived certificate (should be ignored)
                Arguments.of("Archived Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.DECRYPT, KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, true,
                        false, false),

                // 5. Certificate with wrong state (should be ignored)
                Arguments.of("Wrong State Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.DECRYPT, KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.PENDING_APPROVAL, CertificateValidationStatus.VALID, false,
                        false, false),

                // 6. Certificate with a deactivated private RSA key
                Arguments.of("Deactivated RSA Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.DECRYPT, KeyUsage.SIGN), KeyState.DEACTIVATED)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, false),

                // 7. Certificate with a wrong private RSA key usage
                Arguments.of("Wrong private key usage RSA Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.WRAP, KeyUsage.UNWRAP), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, false),

                // 8. Certificate with a wrong public RSA key usage
                Arguments.of("Wrong public key usage RSA Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.WRAP, KeyUsage.UNWRAP), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.DECRYPT, KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, false),

                // 9. Certificate with an invalid RSA key type
                Arguments.of("Secret RSA Cert",
                        List.of(new KeyItemData(KeyType.SECRET_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, false),

                // 10. Certificate with a non RSA/ECDSA key algorithm
                Arguments.of("Falcon Cert",
                        List.of(),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.FALCON, List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, false),

                // 11. Certificate with a wrong key usage for ECDSA public key
                Arguments.of("Wrong usage public ECDSA Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, List.of(KeyUsage.WRAP), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, false),

                // 12. Certificate with a deactivated private ECDSA key
                Arguments.of("Deactivated ECDSA Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA, List.of(KeyUsage.SIGN), KeyState.DEACTIVATED)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, false),

                // 13. Certificate with a wrong private ECDSA key usage
                Arguments.of("Wrong usage private ECDSA Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA, List.of(KeyUsage.WRAP), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, false),

                // 14. Certificate with an invalid ECDSA key type
                Arguments.of("Secret ECDSA Cert",
                        List.of(new KeyItemData(KeyType.SECRET_KEY, KeyAlgorithm.ECDSA, List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, false),

                // 15. Test with intuneEnabled = true (only RSA acceptable)
                Arguments.of("RSA Cert Intune",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.DECRYPT, KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true, true),

                // 16. Test with intuneEnabled = true (ECDSA not acceptable)
                Arguments.of("ECDSA Cert Intune",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true, false),

                // 17. Certificate with expiring status (should be accepted)
                Arguments.of("Expiring Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.DECRYPT, KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.EXPIRING, false,
                        false, true),

                // 18. Certificate with invalid status (should be ignored)
                Arguments.of("Invalid Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.DECRYPT, KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.INVALID, false,
                        false, false),

                // 19. RSA Certificate with missing usages (should be ignored)
                Arguments.of("Wrong private and public key usage RSA Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, false),

                // 20. Multiple private keys, all valid (should be accepted)
                Arguments.of("Multiple Valid Private Keys",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(
                                new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.DECRYPT, KeyUsage.SIGN), KeyState.ACTIVE),
                                new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.DECRYPT, KeyUsage.SIGN), KeyState.ACTIVE)
                        ),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, true),

                // 21. Multiple private keys, one invalid state (should be rejected)
                Arguments.of("Multiple Private Keys, One Inactive",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(
                                new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.DECRYPT, KeyUsage.SIGN), KeyState.ACTIVE),
                                new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.DECRYPT, KeyUsage.SIGN), KeyState.DEACTIVATED)
                        ),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, false),

                // 22. Multiple private keys, one missing SIGN usage (should be rejected)
                Arguments.of("Multiple Private Keys, One Missing Sign",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(
                                new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.DECRYPT, KeyUsage.SIGN), KeyState.ACTIVE),
                                new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.DECRYPT), KeyState.ACTIVE)
                        ),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, false),

                // 23. Multiple public keys, one private key (should be accepted)
                Arguments.of("Multiple Public Keys",
                        List.of(
                                new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY), KeyState.ACTIVE),
                                new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY), KeyState.ACTIVE)
                        ),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.DECRYPT, KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, true)

        );
    }

    // Arguments: testCaseName, publicKeys, privateKeys, certState, validationStatus, archived,
    //            withTokenProfile, extendedKeyUsages, extendedKeyUsageCritical, workflowType,
    //            qualifiedTimestamp, qcCompliance (nullable Boolean), expectedResult
    public static Stream<Arguments> provideDigitalSigningAcceptableTestData() {
        return Stream.of(
                // 1. RSA cert, token profile present, non-TSP workflow → accepted
                Arguments.of("RSA Cert RAW_SIGNING",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true, List.of(), false, SigningWorkflowType.RAW_SIGNING,
                        false, null, true),

                // 2. ECDSA cert, token profile present, non-TSP workflow → accepted
                Arguments.of("ECDSA Cert CONTENT_SIGNING",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.ECDSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true, List.of(), false, SigningWorkflowType.CONTENT_SIGNING,
                        false, null, true),

                // 3. Expiring cert, token profile present, CONTENT_SIGNING → accepted
                Arguments.of("Expiring Cert CONTENT_SIGNING",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.EXPIRING, false,
                        true, List.of(), false, SigningWorkflowType.CONTENT_SIGNING,
                        false, null, true),

                // 4. Falcon cert, token profile present, RAW_SIGNING → accepted
                Arguments.of("Falcon Cert RAW_SIGNING",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.FALCON, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.FALCON, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true, List.of(), false, SigningWorkflowType.RAW_SIGNING,
                        false, null, true),

                // 5. Timestamping cert, exclusively TSA EKU, critical, non-qualified → accepted
                Arguments.of("Timestamping Cert with TSA EKU (non-qualified)",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true, List.of(SystemOid.TIME_STAMPING.getOid()), true, SigningWorkflowType.TIMESTAMPING,
                        false, null, true),

                // 6. Timestamping cert, multiple EKUs including TSA OID → rejected (RFC 3161: MUST have only id-kp-timeStamping)
                Arguments.of("Timestamping Cert with multiple EKUs including TSA",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true, List.of("1.3.6.1.5.5.7.3.3", SystemOid.TIME_STAMPING.getOid()), true, SigningWorkflowType.TIMESTAMPING,
                        false, null, false),

                // 7. No key → rejected
                Arguments.of("No Key Cert",
                        List.of(),
                        List.of(),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, List.of(), false, SigningWorkflowType.RAW_SIGNING,
                        false, null, false),

                // 8. Archived → rejected
                Arguments.of("Archived Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, true,
                        true, List.of(), false, SigningWorkflowType.RAW_SIGNING,
                        false, null, false),

                // 9. Wrong state → rejected
                Arguments.of("Wrong State Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.PENDING_APPROVAL, CertificateValidationStatus.VALID, false,
                        true, List.of(), false, SigningWorkflowType.RAW_SIGNING,
                        false, null, false),

                // 10. Wrong validation status → rejected
                Arguments.of("Invalid Status Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.REVOKED, false,
                        true, List.of(), false, SigningWorkflowType.RAW_SIGNING,
                        false, null, false),

                // 11. No private key → rejected
                Arguments.of("No Private Key Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true, List.of(), false, SigningWorkflowType.RAW_SIGNING,
                        false, null, false),

                // 12. Inactive private key → rejected
                Arguments.of("Inactive Private Key Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.DEACTIVATED)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true, List.of(), false, SigningWorkflowType.RAW_SIGNING,
                        false, null, false),

                // 13. Private key missing SIGN usage → rejected
                Arguments.of("No Sign Usage Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.DECRYPT), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true, List.of(), false, SigningWorkflowType.RAW_SIGNING,
                        false, null, false),

                // 14. No token profile → rejected
                Arguments.of("No Token Profile Cert",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        false, List.of(), false, SigningWorkflowType.RAW_SIGNING,
                        false, null, false),

                // 15. Timestamping workflow, TSA EKU missing → rejected
                Arguments.of("Timestamping Cert without TSA EKU",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true, List.of(), true, SigningWorkflowType.TIMESTAMPING,
                        false, null, false),

                // 16. Timestamping workflow, only unrelated EKU present → rejected
                Arguments.of("Timestamping Cert with wrong EKU only",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true, List.of("1.3.6.1.5.5.7.3.3"), true, SigningWorkflowType.TIMESTAMPING,
                        false, null, false),

                // 17. Multiple private keys, all valid, token profile present → accepted
                Arguments.of("Multiple Valid Private Keys",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(
                                new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE),
                                new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)
                        ),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true, List.of(), false, SigningWorkflowType.RAW_SIGNING,
                        false, null, true),

                // 18. Multiple private keys, one inactive → rejected
                Arguments.of("Multiple Private Keys, One Inactive",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(
                                new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE),
                                new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.DEACTIVATED)
                        ),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true, List.of(), false, SigningWorkflowType.RAW_SIGNING,
                        false, null, false),

                // 19. Timestamping cert, TSA EKU exclusive but EKU extension not critical → rejected (RFC 3161: MUST be critical)
                Arguments.of("Timestamping Cert with TSA EKU non-critical",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true, List.of(SystemOid.TIME_STAMPING.getOid()), false, SigningWorkflowType.TIMESTAMPING,
                        false, null, false),

                // 20. Qualified timestamping requested but qcCompliance not set → rejected
                Arguments.of("Qualified Timestamping Cert without QcCompliance",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true, List.of(SystemOid.TIME_STAMPING.getOid()), true, SigningWorkflowType.TIMESTAMPING,
                        true, null, false),

                // 21. Qualified timestamping, TSA EKU critical, qcCompliance=true → accepted
                Arguments.of("Qualified Timestamping Cert with QcCompliance",
                        List.of(new KeyItemData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.VERIFY), KeyState.ACTIVE)),
                        List.of(new KeyItemData(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, List.of(KeyUsage.SIGN), KeyState.ACTIVE)),
                        CertificateState.ISSUED, CertificateValidationStatus.VALID, false,
                        true, List.of(SystemOid.TIME_STAMPING.getOid()), true, SigningWorkflowType.TIMESTAMPING,
                        true, true, true)
        );
    }
}

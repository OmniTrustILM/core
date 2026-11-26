package com.otilm.core.signing;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * The Signing Profiles whose stored versions hold one certificate, which therefore cannot be deleted. A superseded
 * version keeps its certificate because the raw-signing key binding reads a key's signing history from the stored
 * versions, so only deleting the Signing Profile releases it.
 *
 * @param currentVersionProfiles names of the profiles whose current version holds the certificate, sorted
 * @param supersededOnlyProfiles names of the profiles that hold it only in superseded versions, sorted
 */
public record SigningProfileCertificateUse(List<String> currentVersionProfiles, List<String> supersededOnlyProfiles) {

    public SigningProfileCertificateUse {
        currentVersionProfiles = List.copyOf(currentVersionProfiles);
        supersededOnlyProfiles = List.copyOf(supersededOnlyProfiles);
    }

    /** The use of each certificate any of the versions holds; a certificate none holds has no entry. */
    public static Map<UUID, SigningProfileCertificateUse> byCertificate(
            Collection<CertificateHoldingVersion> versions) {
        return versions
                .stream()
                .collect(Collectors
                        .groupingBy(CertificateHoldingVersion::certificateUuid,
                                Collectors.collectingAndThen(Collectors.toList(), SigningProfileCertificateUse::of)));
    }

    private static SigningProfileCertificateUse of(List<CertificateHoldingVersion> versionsOfOneCertificate) {
        SortedSet<String> currentVersionNames = new TreeSet<>();
        SortedSet<String> supersededVersionNames = new TreeSet<>();
        for (CertificateHoldingVersion version : versionsOfOneCertificate) {
            if (version.isCurrent()) {
                currentVersionNames.add(version.signingProfileName());
            } else {
                supersededVersionNames.add(version.signingProfileName());
            }
        }
        supersededVersionNames.removeAll(currentVersionNames);
        return new SigningProfileCertificateUse(List.copyOf(currentVersionNames), List.copyOf(supersededVersionNames));
    }

    /** Why the certificate cannot be deleted, worded to follow "it is" or "Certificate is". */
    public String reason() {
        List<String> parts = new ArrayList<>();
        if (!currentVersionProfiles.isEmpty()) {
            parts
                    .add("used by the current version of Signing Profile(s): "
                            + String.join(", ", currentVersionProfiles));
        }
        if (!supersededOnlyProfiles.isEmpty()) {
            parts
                    .add("kept by superseded versions of Signing Profile(s) (released only by deleting the Signing Profile): "
                            + String.join(", ", supersededOnlyProfiles));
        }
        return String.join("; ", parts);
    }

    public String deleteRefusal(String certificateName, UUID certificateUuid) {
        return "Could not delete certificate %s with UUID %s: it is %s."
                .formatted(certificateName, certificateUuid, reason());
    }
}

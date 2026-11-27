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
 * versions, so only deleting the Signing Profile releases it, and a profile with signing records cannot be deleted
 * until they are.
 *
 * @param currentVersionProfiles names of the profiles whose current version holds the certificate, sorted
 * @param supersededOnlyProfiles names of the profiles that hold it only in superseded versions, sorted
 */
public record SigningProfileCertificateUse(List<String> currentVersionProfiles, List<String> supersededOnlyProfiles) {

    public SigningProfileCertificateUse {
        currentVersionProfiles = List.copyOf(currentVersionProfiles);
        supersededOnlyProfiles = List.copyOf(supersededOnlyProfiles);
    }

    /** The use of each certificate any of the holds names; a certificate none names has no entry. */
    public static Map<UUID, SigningProfileCertificateUse> byCertificate(Collection<CertificateHold> holds) {
        return holds
                .stream()
                .collect(Collectors
                        .groupingBy(CertificateHold::certificateUuid,
                                Collectors.collectingAndThen(Collectors.toList(), SigningProfileCertificateUse::of)));
    }

    private static SigningProfileCertificateUse of(List<CertificateHold> holdsOnOneCertificate) {
        SortedSet<String> currentVersionNames = new TreeSet<>();
        SortedSet<String> supersededVersionNames = new TreeSet<>();
        for (CertificateHold hold : holdsOnOneCertificate) {
            if (hold.currentVersion()) {
                currentVersionNames.add(hold.signingProfileName());
            } else {
                supersededVersionNames.add(hold.signingProfileName());
            }
        }
        supersededVersionNames.removeAll(currentVersionNames);
        return new SigningProfileCertificateUse(List.copyOf(currentVersionNames), List.copyOf(supersededVersionNames));
    }

    public String deleteRefusal(String certificateName, UUID certificateUuid) {
        return "Could not delete certificate %s with UUID %s: it is %s."
                .formatted(certificateName, certificateUuid, reason());
    }

    /** The refusal as the certificate's event history records it. */
    public String historyMessage() {
        return "Certificate is " + reason();
    }

    private String reason() {
        List<String> parts = new ArrayList<>();
        if (!currentVersionProfiles.isEmpty()) {
            parts
                    .add("used by the current version of Signing Profile(s): "
                            + String.join(", ", currentVersionProfiles));
        }
        if (!supersededOnlyProfiles.isEmpty()) {
            parts
                    .add("kept by superseded versions of Signing Profile(s) (released only by deleting the Signing Profile, which first requires deleting its signing records): "
                            + String.join(", ", supersededOnlyProfiles));
        }
        return String.join("; ", parts);
    }
}

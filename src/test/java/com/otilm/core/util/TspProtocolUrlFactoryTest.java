package com.otilm.core.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit test for {@link TspProtocolUrlFactory} — the pure composer of externally-reachable TSP protocol URLs.
 * The methods hold no request dependency and perform plain string concatenation, so every case is driven
 * directly with literal inputs. These assertions pin the exact wire path surfaced to operators in profile DTOs;
 * a change here is a change to the client-facing contract.
 */
class TspProtocolUrlFactoryTest {

    private static final String BASE_URL = "https://czertainly.example.com";

    @Test
    void forTspProfile_composesProtocolPathWithProfileName() {
        // given
        var tspProfileName = "my-tsp-profile";

        // when
        String url = TspProtocolUrlFactory.forTspProfile(BASE_URL, tspProfileName);

        // then
        assertEquals("https://czertainly.example.com/v1/protocols/tsp/my-tsp-profile", url);
    }

    @Test
    void forSigningProfile_composesProtocolPathWithSigningProfilesSegment() {
        // given
        var signingProfileName = "my-signing-profile";

        // when
        String url = TspProtocolUrlFactory.forSigningProfile(BASE_URL, signingProfileName);

        // then
        assertEquals("https://czertainly.example.com/v1/protocols/tsp/signingProfiles/my-signing-profile", url);
    }

    @Test
    void signingProfile_andTspProfile_shareBasePathButSigningProfileAddsExtraSegment() {
        // given the same name resolved through both factory methods
        var profileName = "shared-name";

        // when
        String tspProfileUrl = TspProtocolUrlFactory.forTspProfile(BASE_URL, profileName);
        String signingProfileUrl = TspProtocolUrlFactory.forSigningProfile(BASE_URL, profileName);

        // then both anchor the same base path, but the signing-profile URL carries the extra "signingProfiles" segment
        assertEquals(BASE_URL + "/v1/protocols/tsp/shared-name", tspProfileUrl);
        assertEquals(BASE_URL + "/v1/protocols/tsp/signingProfiles/shared-name", signingProfileUrl);
    }

    @Test
    void forTspProfile_concatenatesBaseUrlVerbatimWithoutNormalization() {
        // given a base URL carrying a context path; the web layer is responsible for supplying it clean
        var baseUrlWithContextPath = "https://czertainly.example.com/api";

        // when
        String url = TspProtocolUrlFactory.forTspProfile(baseUrlWithContextPath, "profile");

        // then
        assertEquals("https://czertainly.example.com/api/v1/protocols/tsp/profile", url);
    }
}

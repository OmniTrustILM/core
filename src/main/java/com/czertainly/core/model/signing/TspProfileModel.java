package com.czertainly.core.model.signing;

import java.util.UUID;

/**
 * Model layer representation of a TSP Profile used on the TSP timestamping hot path.
 *
 * @param uuid        UUID of the TSP Profile.
 * @param name        Name of the TSP Profile.
 * @param description Optional description.
 * @param enabled     Whether the profile is currently enabled.
 * @param signingUrl  URL for TSP signing, or {@code null} if no default signing profile is configured yet.
 */
public record TspProfileModel(
        UUID uuid,
        String name,
        String description,
        boolean enabled,
        String signingUrl
) {}

package com.otilm.core.model.signing;

import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.scheme.SigningSchemeModel;
import com.otilm.core.model.signing.workflow.SigningWorkflow;

import java.util.List;
import java.util.UUID;

/**
 * Model layer representation of a Signing Profile.
 *
 * <p>The workflow ({@code W}) is a sealed {@link SigningWorkflow} subtype and the signing scheme
 * ({@code SM}) is a sealed {@link SigningSchemeModel} subtype. Both are further split into
 * managed and delegated record variants, so all scheme-scoped fields are only accessible on the
 * correct variant via pattern matching — enforced at compile time.</p>
 *
 * <p>This model is shaped to be safely cached: it holds <strong>only UUIDs</strong> for objects
 * owned by other caches (Time Quality Configuration, certificate-chain) or other repositories
 * (RA profile, token profile, connectors). It never embeds entities or peer-cache model objects.</p>
 *
 * @param uuid              UUID of the Signing Profile.
 * @param name              Name of the Signing Profile.
 * @param description       Optional description.
 * @param version           Current version number.
 * @param enabled           Whether the profile is currently enabled.
 * @param enabledProtocols  Protocols enabled on this profile (e.g. TSP).
 * @param workflow          Workflow-type-specific configuration.
 * @param signingScheme     Signing scheme configuration.
 * @param recordPolicy      Signing record policy (what is captured, retention, persistence mode).
 * @param <W>               Concrete {@link SigningWorkflow} subtype.
 * @param <SM>              Concrete {@link SigningSchemeModel} subtype.
 */
@SuppressWarnings("java:S119")
public record SigningProfileModel<W extends SigningWorkflow, SM extends SigningSchemeModel>(
        UUID uuid,
        String name,
        String description,
        int version,
        boolean enabled,
        List<SigningProtocol> enabledProtocols,
        W workflow,
        SM signingScheme,
        SigningRecordPolicyModel recordPolicy
) {}

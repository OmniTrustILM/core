package com.otilm.core.service;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.raprofile.AttributeSetMergeMode;
import com.otilm.api.model.core.raprofile.RaProfileCertificateRequestAttributesDto;
import com.otilm.api.model.core.raprofile.RaProfileCertificateRequestAttributesUpdateDto;
import com.otilm.core.dao.entity.RaProfile;

import java.util.List;

/**
 * Orchestrates the platform-owned static RA-Profile request-attribute set, the Core-side value-source bindings,
 * the editable platform default set, and the per-(RA Profile, operation) resolution order.
 */
public interface RaProfileCertificateRequestAttributeService {

    /**
     * Resolves the ordered request-attribute set for an issue/sign operation on the RA Profile:
     * static set → connector dynamic set → platform default set, combined per {@code mode}, with value-source bindings applied.
     *
     * @param raProfile the RA Profile (its authority's connector supplies the dynamic set, if any)
     * @param mode      the merge mode; {@code null} defaults to {@link AttributeSetMergeMode#MERGE}
     */
    List<BaseAttribute> resolveIssueAttributeSet(RaProfile raProfile, AttributeSetMergeMode mode)
            throws ConnectorException, NotFoundException;

    /**
     * Resolves the ordered request-attribute set using the merge mode persisted on the RA Profile
     * (defaults to {@link AttributeSetMergeMode#MERGE} when unset).
     */
    List<BaseAttribute> resolveIssueAttributeSet(RaProfile raProfile)
            throws ConnectorException, NotFoundException;

    /** Returns the parsed static request-attribute definitions stored on the RA Profile (empty if none). */
    List<BaseAttribute> getStaticSet(RaProfile raProfile);

    /** Builds the view DTO of the RA Profile's request-attribute configuration (static set, merge mode, bindings, strictness). */
    RaProfileCertificateRequestAttributesDto getConfiguration(RaProfile raProfile);

    /** Persists the RA Profile's request-attribute configuration: static definitions, merge mode, bindings, strictness. */
    void updateConfiguration(RaProfile raProfile, RaProfileCertificateRequestAttributesUpdateDto request);

    /** Returns the editable platform default set (seeded from {@code CsrAttributes} when unset). */
    List<BaseAttribute> getDefaultSet();

    /** Effective strictness: per-RA-Profile value, else the platform default, else lenient (false). */
    boolean resolveExternalCsrValidationStrict(RaProfile raProfile);
}

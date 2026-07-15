package com.otilm.core.certificate.request;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.service.RaProfileCertificateRequestAttributeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Objects;

/**
 * Resolves the issuance attribute definitions for a certificate request: the configured request-attribute
 * set narrowed to the {@link DataAttributeV3} definitions the projection pipeline consumes.
 *
 * <p>Shared by the platform-built issue path and the register path — so both project structured attribute values
 * against the same resolved set that EST {@code /csrattrs} and external-CSR validation use.
 */
@Component
public class IssuanceDefinitionResolver {

    private static final Logger logger = LoggerFactory.getLogger(IssuanceDefinitionResolver.class);

    private final RaProfileCertificateRequestAttributeService requestAttributeService;

    public IssuanceDefinitionResolver(RaProfileCertificateRequestAttributeService requestAttributeService) {
        this.requestAttributeService = requestAttributeService;
    }

    /**
     * Resolves the configured request-attribute set for the profile, keeping only v3 definitions — non-v3
     * definitions cannot carry a {@code fieldMapping}, so the projection has no use for them.
     *
     * <p>When the resolved set carries no v3 definitions (a v2 authority connector supplying the whole set),
     * falls back to the v3 definitions of the editable platform default set, so a non-v3 authority never
     * silently empties the projection. When no v3 definitions exist anywhere, throws {@link ValidationException}.
     */
    public List<DataAttributeV3> resolve(RaProfile raProfile) throws ConnectorException, NotFoundException {
        Objects.requireNonNull(raProfile, "raProfile is required to resolve issuance definitions");
        List<BaseAttribute> resolved = requestAttributeService.resolveIssueAttributeSet(raProfile);
        List<DataAttributeV3> definitions = onlyV3(resolved);
        int droppedNonV3 = resolved.size() - definitions.size();
        if (droppedNonV3 > 0) {
            logger.debug("Ignoring {} non-v3 request attribute definition(s) for RA profile {}; structured CSR enrichment requires v3 definitions",
                    droppedNonV3, raProfile.getName());
        }
        if (definitions.isEmpty() && !resolved.isEmpty()) {
            logger.warn("Resolved request-attribute set for RA profile {} carries no v3 definitions; falling back to the platform default set",
                    raProfile.getName());
            definitions = onlyV3(requestAttributeService.getDefaultSet(raProfile));
        }
        if (definitions.isEmpty()) {
            throw new ValidationException("No projectable request attribute definitions available for RA profile "
                    + raProfile.getName()
                    + ": neither the resolved request-attribute set nor the platform default set contains v3 definitions."
                    + " Configure request attributes on the RA profile or in the platform settings.");
        }
        return definitions;
    }

    private static List<DataAttributeV3> onlyV3(List<BaseAttribute> attributes) {
        return attributes.stream()
                .filter(DataAttributeV3.class::isInstance)
                .map(DataAttributeV3.class::cast)
                .toList();
    }
}

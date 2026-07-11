package com.otilm.core.certificate.request;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.mapping.FieldMapping;
import com.otilm.api.model.common.attribute.v3.mapping.FieldType;
import com.otilm.api.model.common.attribute.v3.mapping.RdnMappedField;
import com.otilm.core.attribute.CsrAttributes;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.service.v2.ExtendedAttributeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Resolves the issuance attribute definitions for a certificate request: the connector-supplied v3
 * definitions (which carry {@link FieldMapping}) merged over the static {@link CsrAttributes} default set.
 *
 * <p>Shared by the platform-built issue path and the register path — both orchestrated in
 * {@code ClientOperationServiceImpl} — so both project structured attribute values against an identical
 * definition set.
 */
@Component
public class IssuanceDefinitionResolver {

    private static final Logger logger = LoggerFactory.getLogger(IssuanceDefinitionResolver.class);

    private final ExtendedAttributeService extendedAttributeService;

    public IssuanceDefinitionResolver(ExtendedAttributeService extendedAttributeService) {
        this.extendedAttributeService = extendedAttributeService;
    }

    /**
     * Prefers connector-supplied v3 definitions (which carry {@code fieldMapping}) and falls back to the static
     * CSR default set. Returns the defaults unchanged when {@code raProfile} is null.
     */
    public List<DataAttributeV3> resolve(RaProfile raProfile) throws ConnectorException, NotFoundException {
        List<DataAttributeV3> defaults = CsrAttributes.csrAttributesAsDataAttributesV3();
        if (raProfile == null) {
            return defaults;
        }
        List<BaseAttribute> connectorAttrs = extendedAttributeService.listIssueCertificateAttributes(raProfile);
        List<DataAttributeV3> connectorDefs = connectorAttrs.stream()
                .filter(DataAttributeV3.class::isInstance)
                .map(DataAttributeV3.class::cast)
                .toList();
        int droppedNonV3 = connectorAttrs.size() - connectorDefs.size();
        if (droppedNonV3 > 0) {
            logger.debug("Ignoring {} non-v3 connector issue attribute(s) for RA profile {}; structured CSR enrichment requires a v3 authority connector",
                    droppedNonV3, raProfile.getName());
        }
        return mergeIssuanceDefinitions(defaults, connectorDefs, OidHandler.getCodeToOidMap());
    }

    /**
     * Merges connector-supplied v3 definitions with the static default set. Connector definitions take
     * precedence: any default whose RDN field mapping is also claimed by a connector definition is dropped.
     * Connector definitions without a {@code fieldMapping} (connector-specific fields) carry no RDN claim
     * and are always retained.
     */
    static List<DataAttributeV3> mergeIssuanceDefinitions(List<DataAttributeV3> defaults,
                                                          List<DataAttributeV3> connectorDefs,
                                                          Map<String, String> codeToOid) {
        Set<String> claimedRdns = connectorDefs.stream()
                .flatMap(d -> rdnFields(d).map(f -> normalizeRdn(f.getRdn(), codeToOid)))
                .collect(Collectors.toSet());

        List<DataAttributeV3> filteredDefaults = defaults.stream()
                .filter(d -> rdnFields(d)
                        .map(f -> normalizeRdn(f.getRdn(), codeToOid))
                        .noneMatch(claimedRdns::contains))
                .toList();

        List<DataAttributeV3> merged = new ArrayList<>(connectorDefs);
        merged.addAll(filteredDefaults);
        return merged;
    }

    /**
     * Streams the RDN-typed mapped fields of a definition, tolerating connector payloads that carry a
     * null {@code fieldMapping} or a mapping with null {@code fields}.
     */
    private static Stream<RdnMappedField> rdnFields(DataAttributeV3 def) {
        FieldMapping fm = def.getFieldMapping();
        if (fm == null || fm.getFields() == null) {
            return Stream.empty();
        }
        return fm.getFields().stream()
                .filter(f -> f.getFieldType() == FieldType.RDN)
                .map(RdnMappedField.class::cast);
    }

    private static String normalizeRdn(String rdn, Map<String, String> codeToOid) {
        return codeToOid == null ? rdn : codeToOid.getOrDefault(rdn, rdn);
    }
}

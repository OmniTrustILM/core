package db.migration;

import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.czertainly.core.model.compliance.ComplianceResultDto;
import com.czertainly.core.model.compliance.ComplianceResultProviderRulesDto;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.czertainly.core.util.DatabaseMigration;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.OffsetDateTime;
import java.util.*;

/**
 * Migration script for the Json array migration to separate table
 */
@SuppressWarnings("java:S101")
public class V202507311051__MigrateToComplianceProfilesV2 extends BaseJavaMigration {

    private static final Logger logger = LoggerFactory.getLogger(V202507311051__MigrateToComplianceProfilesV2.class);

    private static final ObjectMapper mapper = Jackson2ObjectMapperBuilder.json()
            .featuresToDisable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, DeserializationFeature.FAIL_ON_MISSING_EXTERNAL_TYPE_ID_PROPERTY)
            .modules(new JavaTimeModule())
            .serializationInclusion(JsonInclude.Include.NON_NULL)
            .build();

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202507311051__MigrateToComplianceProfilesV2.getChecksum();
    }

    @Override
    public void migrate(Context context) throws Exception {
        handleNewFunctionGroupEndpoints(context);
        prepareDBStructure(context);
        migrateData(context);
        cleanDbStructureAndData(context);
    }

    private void handleNewFunctionGroupEndpoints(Context context) throws SQLException {
        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("listRules", "GET /v2/complianceProvider/{kind}/rules");
        endpoints.put("getRulesBatch", "POST /v2/complianceProvider/{kind}/rules");
        endpoints.put("getRule", "GET /v2/complianceProvider/{kind}/rules/{ruleUuid}");
        endpoints.put("listGroups", "GET /v2/complianceProvider/{kind}/groups");
        endpoints.put("getGroup", "GET /v2/complianceProvider/{kind}/groups/{groupUuid}");
        endpoints.put("getGroupRules", "GET /v2/complianceProvider/{kind}/groups/{groupUuid}/rules");
        endpoints.put("checkCompliance", "POST /v2/complianceProvider/{kind}/compliance");

        try (final PreparedStatement insertFunctionGroupStatement = context.getConnection().prepareStatement("INSERT INTO function_group (uuid, code, name) VALUES (?,?,?)");
             final PreparedStatement insertEndpointStatement = context.getConnection().prepareStatement("INSERT INTO endpoint (uuid, context, \"method\", name, required, function_group_uuid) VALUES (?,?,?,?,?,?)")) {
            UUID functionGroupUuid = UUID.randomUUID();
            insertFunctionGroupStatement.setObject(1, functionGroupUuid);
            insertFunctionGroupStatement.setString(2, FunctionGroupCode.COMPLIANCE_PROVIDER_V2.name());
            insertFunctionGroupStatement.setString(3, FunctionGroupCode.COMPLIANCE_PROVIDER_V2.getCode());
            insertFunctionGroupStatement.executeUpdate();

            insertEndpointStatement.setBoolean(5, true);
            insertEndpointStatement.setObject(6, functionGroupUuid);
            for (var endpoint : endpoints.entrySet()) {
                String[] endpointContext = endpoint.getValue().split(" ");
                insertEndpointStatement.setObject(1, UUID.randomUUID());
                insertEndpointStatement.setString(2, endpointContext[1]);
                insertEndpointStatement.setString(3, endpointContext[0]);
                insertEndpointStatement.setString(4, endpoint.getKey());
                insertEndpointStatement.addBatch();
            }
            logger.debug("Executing batch insert with {} compliance provider v2 endpoints.", endpoints.size());
            insertEndpointStatement.executeBatch();
        }
    }

    private void prepareDBStructure(Context context) throws SQLException {
        String sqlCommands = """
                UPDATE compliance_profile_rule SET attributes = NULL WHERE lower("attributes") = 'null' OR attributes = '[]' OR attributes = '';
                ALTER TABLE compliance_profile_rule
                    ADD COLUMN connector_uuid UUID NULL,
                    ADD COLUMN kind TEXT NULL,
                    ADD COLUMN compliance_rule_uuid UUID NULL,
                    ADD COLUMN compliance_group_uuid UUID NULL,
                    ADD COLUMN internal_rule_uuid UUID NULL,
                    ADD COLUMN resource TEXT NULL,
                    ADD COLUMN type TEXT NULL,
                    ALTER COLUMN attributes TYPE JSONB USING attributes::jsonb,
                    ALTER COLUMN compliance_profile_uuid SET NOT NULL,
                    DROP COLUMN i_author,
                    DROP COLUMN i_cre,
                    DROP COLUMN i_upd,
                    DROP CONSTRAINT "compliance_profile_rule_to_compliance_profile",
                    ADD CONSTRAINT fk_compliance_profile_rule_to_compliance_profile FOREIGN KEY (compliance_profile_uuid) REFERENCES compliance_profile(uuid) ON UPDATE CASCADE ON DELETE CASCADE,
                    ADD CONSTRAINT fk_compliance_profile_rule_to_connector FOREIGN KEY (connector_uuid) REFERENCES connector(uuid) ON UPDATE CASCADE ON DELETE RESTRICT,
                    ADD CONSTRAINT fk_compliance_profile_rule_to_rule FOREIGN KEY (internal_rule_uuid) REFERENCES rule(uuid) ON UPDATE CASCADE ON DELETE RESTRICT;
                
                UPDATE compliance_profile_rule SET compliance_rule_uuid = rule_uuid, resource = 'CERTIFICATE', type = 'X509';
                
                ALTER TABLE compliance_profile_rule
                    DROP COLUMN rule_uuid;
                
                CREATE TABLE compliance_profile_association
                (
                    "uuid"                      UUID    NOT NULL,
                    "compliance_profile_uuid"   UUID    NOT NULL,
                    "resource"                  TEXT    NOT NULL,
                    "object_uuid"               UUID    NOT NULL,
                    PRIMARY KEY ("uuid")
                );
                
                ALTER TABLE compliance_profile_association
                    ADD CONSTRAINT fk_compliance_profile_association_to_compliance_profile FOREIGN KEY (compliance_profile_uuid) REFERENCES compliance_profile(uuid) ON UPDATE CASCADE ON DELETE RESTRICT;
                
                UPDATE certificate SET compliance_result = NULL WHERE lower("compliance_result") = 'null' OR compliance_result = '{}' OR compliance_result = '';
                ALTER TABLE certificate
                    ALTER COLUMN compliance_result TYPE JSONB USING compliance_result::jsonb;
                
                ALTER TABLE certificate_request
                    ADD COLUMN compliance_status TEXT NULL,
                    ADD COLUMN compliance_result JSONB NULL;
                
                UPDATE certificate_request SET compliance_status = 'NOT_CHECKED';
                ALTER TABLE certificate_request
                    ALTER COLUMN compliance_status SET NOT NULL;
                
                ALTER TABLE cryptographic_key_item
                    ADD COLUMN compliance_status TEXT NULL,
                    ADD COLUMN compliance_result JSONB NULL;
                
                UPDATE cryptographic_key_item SET compliance_status = 'NOT_CHECKED';
                ALTER TABLE cryptographic_key_item
                    ALTER COLUMN compliance_status SET NOT NULL;
                """;
        try (final Statement statement = context.getConnection().createStatement()) {
            statement.execute(sqlCommands);
        }
    }

    private void migrateData(Context context) throws SQLException, CertificateOperationException {
        try (final Statement statement = context.getConnection().createStatement();
             final PreparedStatement updateCertComplianceResultStatement = context.getConnection().prepareStatement("UPDATE certificate SET compliance_result = ?::jsonb WHERE uuid = ?");
             final PreparedStatement insertProfileAssocStatement = context.getConnection().prepareStatement("INSERT INTO compliance_profile_association(uuid, compliance_profile_uuid, resource, object_uuid) VALUES (?,?,?,?)");
             final PreparedStatement updateProfileRuleAssocStatement = context.getConnection().prepareStatement("UPDATE compliance_profile_rule SET attributes = ?::jsonb WHERE uuid = ?");
             final PreparedStatement insertProfileGroupAssocStatement = context.getConnection().prepareStatement("INSERT INTO compliance_profile_rule(uuid, compliance_profile_uuid, compliance_group_uuid) VALUES (?,?,?)")) {

            // create map of rule UUID to connector UUID and kind
            Map<UUID, String> ruleConnectorKindMap = new HashMap<>();
            Map<UUID, Map<String, DataAttributeV2>> ruleAttributesMap = new HashMap<>();
            try (ResultSet rulesRows = statement.executeQuery("SELECT uuid, connector_uuid, kind, attributes FROM compliance_rule")) {
                while (rulesRows.next()) {
                    UUID ruleUuid = rulesRows.getObject("uuid", UUID.class);
                    ruleConnectorKindMap.put(ruleUuid, rulesRows.getString("connector_uuid") + "|" + rulesRows.getString("kind"));

                    String attributesStr = rulesRows.getString("attributes");
                    if (attributesStr != null && !attributesStr.isBlank()) {
                        try {
                            Map<String, DataAttributeV2> attributes = Arrays.stream(mapper.readValue(attributesStr, BaseAttribute[].class))
                                    .filter(DataAttributeV2.class::isInstance)
                                    .collect(HashMap::new, (m, a) -> m.put(a.getName(), (DataAttributeV2) a), HashMap::putAll);
                            ruleAttributesMap.put(ruleUuid, attributes);
                        } catch (JsonProcessingException ignored) {
                            logger.warn("Skipping invalid attributes of compliance rule with UUID {}.", ruleUuid);
                        }
                    }
                }
            }

            migrateRaProfileAssociations(statement, insertProfileAssocStatement);
            migrateComplianceGroupsToProfileAssociations(statement, insertProfileGroupAssocStatement);
            migrateComplianceProfileRuleAttributes(ruleAttributesMap, statement, updateProfileRuleAssocStatement);
            migrateCertificateComplianceResults(ruleConnectorKindMap, statement, updateCertComplianceResultStatement);
        }
    }

    private void migrateRaProfileAssociations(final Statement statement, final PreparedStatement insertProfileAssocStatement) throws SQLException {
        int count = 0;
        try (ResultSet rows = statement.executeQuery("SELECT ra_profile_uuid, compliance_profile_uuid FROM ra_profile_2_compliance_profile")) {
            while (rows.next()) {
                final UUID raPofileUuid = rows.getObject("ra_profile_uuid", UUID.class);
                final UUID compliancePofileUuid = rows.getObject("compliance_profile_uuid", UUID.class);

                insertProfileAssocStatement.setObject(1, UUID.randomUUID());
                insertProfileAssocStatement.setObject(2, compliancePofileUuid);
                insertProfileAssocStatement.setString(3, Resource.RA_PROFILE.name());
                insertProfileAssocStatement.setObject(4, raPofileUuid);
                insertProfileAssocStatement.addBatch();
                ++count;
            }
        }
        logger.debug("Executing batch insert with {} compliance profile associations.", count);
        insertProfileAssocStatement.executeBatch();
    }

    private void migrateComplianceGroupsToProfileAssociations(final Statement statement, final PreparedStatement insertProfileGroupAssocStatement) throws SQLException {
        // migrate compliance groups to compliance profile associations
        int count = 0;
        try (ResultSet rows = statement.executeQuery("SELECT profile_uuid, group_uuid FROM compliance_profile_2_compliance_group")) {
            while (rows.next()) {
                final UUID groupUuid = rows.getObject("group_uuid", UUID.class);
                final UUID compliancePofileUuid = rows.getObject("profile_uuid", UUID.class);

                insertProfileGroupAssocStatement.setObject(1, UUID.randomUUID());
                insertProfileGroupAssocStatement.setObject(2, compliancePofileUuid);
                insertProfileGroupAssocStatement.setObject(3, groupUuid);
                insertProfileGroupAssocStatement.addBatch();
                ++count;
            }
        }
        logger.debug("Executing batch insert with {} compliance profile group associations.", count);
        insertProfileGroupAssocStatement.executeBatch();

        // update all provider compliance rules to set connector UUID and kind
        String updateComplianceProfileRules = """
                UPDATE compliance_profile_rule
                SET connector_uuid = (SELECT r.connector_uuid FROM compliance_rule AS r WHERE r.uuid = compliance_profile_rule.compliance_rule_uuid),
                    kind = (SELECT r.kind FROM compliance_rule AS r WHERE r.uuid = compliance_profile_rule.compliance_rule_uuid)
                WHERE compliance_rule_uuid IS NOT NULL;
                
                UPDATE compliance_profile_rule
                SET resource = 'CERTIFICATE',
                    connector_uuid = (SELECT g.connector_uuid FROM compliance_group AS g WHERE g.uuid = compliance_profile_rule.compliance_group_uuid),
                    kind = (SELECT g.kind FROM compliance_group AS g WHERE g.uuid = compliance_profile_rule.compliance_group_uuid)
                WHERE compliance_group_uuid IS NOT NULL;
                """;

        count = statement.executeUpdate(updateComplianceProfileRules);
        logger.debug("Updated {} compliance profile rules associations to set connector UUID and kind.", count);
    }

    private void migrateComplianceProfileRuleAttributes(Map<UUID, Map<String, DataAttributeV2>> ruleAttributesMap, final Statement statement, final PreparedStatement updateProfileRuleAssocStatement) throws SQLException {
        int count = 0;
        try (ResultSet rows = statement.executeQuery("SELECT uuid, compliance_rule_uuid, attributes FROM compliance_profile_rule WHERE compliance_rule_uuid IS NOT NULL AND attributes IS NOT NULL")) {
            while (rows.next()) {
                final UUID profileRuleUuid = rows.getObject("uuid", UUID.class);
                final UUID complianceRuleUuid = rows.getObject("compliance_rule_uuid", UUID.class);
                final String ruleAttributesJson = rows.getString("attributes");

                List<RequestAttributeV2> profileRuleAttributes = null;
                try {
                    profileRuleAttributes = mapper.readValue(ruleAttributesJson, new TypeReference<>() {
                    });
                } catch (JsonProcessingException ignored) {
                    logger.warn("Skipping invalid attributes, compliance profile rule with UUID {} will be saved without attributes", profileRuleUuid);
                }

                Map<String, DataAttributeV2> ruleAttributes = ruleAttributesMap.get(complianceRuleUuid);
                if (profileRuleAttributes != null) {
                    if (ruleAttributes == null) {
                        profileRuleAttributes = null;
                    } else {
                        updatedRuleRequestAttributes(profileRuleAttributes, ruleAttributes);
                    }
                }

                String ruleAttributesJsonUpdated = null;
                try {
                    ruleAttributesJsonUpdated = profileRuleAttributes == null ? null : mapper.writeValueAsString(profileRuleAttributes);
                } catch (JsonProcessingException ignored) {
                    logger.warn("Cannot serialize updated attributes, compliance profile rule with UUID {} and original attributes {} will be saved without attributes", profileRuleUuid, ruleAttributesJson);
                }

                updateProfileRuleAssocStatement.setString(1, ruleAttributesJsonUpdated);
                updateProfileRuleAssocStatement.setObject(2, profileRuleUuid);
                updateProfileRuleAssocStatement.addBatch();
                ++count;
            }
        }
        logger.debug("Executing batch update with {} compliance profile rule associations with attributes.", count);
        updateProfileRuleAssocStatement.executeBatch();
    }

    private void updatedRuleRequestAttributes(List<RequestAttributeV2> profileRuleAttributes, Map<String, DataAttributeV2> ruleAttributes) {
        for (RequestAttributeV2 profileRuleAttribute : profileRuleAttributes) {
            if (profileRuleAttribute.getUuid() != null && profileRuleAttribute.getContentType() != null) {
                // skip full attributes
                continue;
            }

            DataAttributeV2 ruleAttribute = ruleAttributes.get(profileRuleAttribute.getName());
            if (ruleAttribute != null) {
                profileRuleAttribute.setUuid(UUID.fromString(ruleAttribute.getUuid()));
                profileRuleAttribute.setContentType(ruleAttribute.getContentType());
            } else {
                if (profileRuleAttribute.getUuid() == null) {
                    profileRuleAttribute.setUuid(UUID.randomUUID());
                }
                if (profileRuleAttribute.getContentType() == null) {
                    profileRuleAttribute.setContentType(AttributeDefinitionUtils.deriveAttributeContentTypeFromContent(profileRuleAttribute.getContent()));
                }
            }
        }
    }

    private void migrateCertificateComplianceResults(final Map<UUID, String> ruleConnectorKindMap, final Statement statement, final PreparedStatement updateCertComplianceResultStatement) throws SQLException, CertificateOperationException {
        int count = 0;
        OffsetDateTime complianceTimestamp = OffsetDateTime.now();

        try (ResultSet certificatesRows = statement.executeQuery("SELECT uuid, compliance_status, compliance_result FROM certificate WHERE compliance_result IS NOT NULL")) {
            while (certificatesRows.next()) {
                final UUID certificateUuid = certificatesRows.getObject("uuid", UUID.class);
                final ComplianceStatus complianceStatus = ComplianceStatus.valueOf(certificatesRows.getString("compliance_status"));
                String complianceResult = certificatesRows.getString("compliance_result");
                try {
                    Map<String, List<String>> complianceResultOld = mapper.readValue(complianceResult, HashMap.class);
                    ComplianceResultDto complianceResultDto = new ComplianceResultDto();
                    complianceResultDto.setTimestamp(complianceTimestamp);
                    complianceResultDto.setStatus(complianceStatus);
                    complianceResultDto.setProviderRules(getComplianceResultProviderRules(ruleConnectorKindMap, complianceResultOld));

                    updateCertComplianceResultStatement.setString(1, mapper.writeValueAsString(complianceResultDto));
                    updateCertComplianceResultStatement.setObject(2, certificateUuid);
                    updateCertComplianceResultStatement.addBatch();
                    ++count;
                } catch (JsonProcessingException e) {
                    throw new CertificateOperationException("Failed to parse compliance result for certificate with UUID " + certificateUuid);
                }
            }
        }

        logger.debug("Executing batch update of compliance result for {} certificates.", count);
        updateCertComplianceResultStatement.executeBatch();
    }

    private List<ComplianceResultProviderRulesDto> getComplianceResultProviderRules(Map<UUID, String> ruleConnectorKindMap, Map<String, List<String>> complianceResultOld) {
        List<String> notApplicable = complianceResultOld.get("na");
        List<String> notCompliant = complianceResultOld.get("nok");
        if ((notApplicable == null || notApplicable.isEmpty()) && (notCompliant == null || notCompliant.isEmpty())) {
            return null;
        }

        Map<String, ComplianceResultProviderRulesDto> providerRulesMap = new HashMap<>();
        if (notApplicable != null) {
            for (String uuid : notApplicable) {
                UUID ruleUuid = UUID.fromString(uuid);
                String connectorKind = ruleConnectorKindMap.get(ruleUuid);
                if (connectorKind == null) {
                    logger.warn("Cannot find connector and kind for not applicable compliance rule with UUID {}", ruleUuid);
                    continue;
                }

                ComplianceResultProviderRulesDto providerRules = providerRulesMap.computeIfAbsent(connectorKind, k -> {
                    String[] parts = k.split("\\|");
                    ComplianceResultProviderRulesDto dto = new ComplianceResultProviderRulesDto();
                    dto.setConnectorUuid(UUID.fromString(parts[0]));
                    dto.setKind(parts[1]);
                    return dto;
                });
                providerRules.getNotApplicable().add(ruleUuid);
            }
        }

        if (notCompliant != null) {
            for (String uuid : notCompliant) {
                UUID ruleUuid = UUID.fromString(uuid);
                String connectorKind = ruleConnectorKindMap.get(ruleUuid);
                if (connectorKind == null) {
                    logger.warn("Cannot find connector and kind for not compliant compliance rule with UUID {}", ruleUuid);
                    continue;
                }

                ComplianceResultProviderRulesDto providerRules = providerRulesMap.computeIfAbsent(connectorKind, k -> {
                    String[] parts = k.split("\\|");
                    ComplianceResultProviderRulesDto dto = new ComplianceResultProviderRulesDto();
                    dto.setConnectorUuid(UUID.fromString(parts[0]));
                    dto.setKind(parts[1]);
                    return dto;
                });
                providerRules.getNotCompliant().add(ruleUuid);
            }
        }

        return providerRulesMap.values().stream().toList();
    }

    private void cleanDbStructureAndData(Context context) throws SQLException {
        try (Statement statement = context.getConnection().createStatement()) {
            statement.addBatch("DROP TABLE compliance_profile_2_compliance_group;");
            statement.addBatch("DROP TABLE ra_profile_2_compliance_profile;");
            statement.addBatch("DROP TABLE compliance_rule;");
            statement.addBatch("DROP TABLE compliance_group;");
            statement.executeBatch();

        }
    }
}
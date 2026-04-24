package com.czertainly.core.migration;

import com.czertainly.api.model.client.attribute.RequestAttributeV2;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.core.compliance.ComplianceStatus;
import com.czertainly.core.model.compliance.ComplianceResultDto;
import com.czertainly.core.util.BaseSpringBootTest;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import db.migration.V202507311051__MigrateToComplianceProfilesV2;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.transaction.annotation.Transactional;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.UUID;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class MigrateToComplianceProfilesV2Test extends BaseSpringBootTest {

    @Autowired
    DataSource dataSource;

    @Autowired
    ObjectMapper objectMapper;

    MigrateToComplianceProfilesV2Test() throws SQLException {
    }

    @Test
    @Transactional
    void testMigration() throws Exception {
        // Use single connection for mock to avoid connection pool exhaustion
        try (Connection mockConnection = dataSource.getConnection()) {
            Context context = Mockito.mock(Context.class);
            when(context.getConnection()).thenReturn(mockConnection);

            recreateOldTables(context);

            V202507311051__MigrateToComplianceProfilesV2 migration = new V202507311051__MigrateToComplianceProfilesV2();
            migration.migrate(context);
        }

        // Use single connection for all assertions
        try (Connection assertConn = dataSource.getConnection()) {
            assertNewFunctionGroupAndEndpointsExists(assertConn);
            assertMigratedDataPresence(assertConn);

            // check cleanup of removed tables
            try (Statement statement = assertConn.createStatement()) {
                Assertions.assertThrows(SQLException.class, () -> statement.executeQuery("SELECT * FROM ra_profile_2_compliance_profile"));
            }
        }
    }

    private void recreateOldTables(Context context) throws SQLException {
        String sqlStructure = """
                        DROP TABLE compliance_profile_association CASCADE;
                        DROP TABLE compliance_profile CASCADE;
                
                        ALTER TABLE certificate
                            ALTER COLUMN compliance_result TYPE TEXT;
                
                        ALTER TABLE certificate_request
                            DROP COLUMN compliance_status,
                            DROP COLUMN compliance_result;
                
                        ALTER TABLE cryptographic_key_item
                            DROP COLUMN compliance_status,
                            DROP COLUMN compliance_result;
                
                        CREATE TABLE compliance_profile (
                            "uuid" uuid NOT NULL,
                            i_author varchar NOT NULL,
                            i_cre timestamp(6) NOT NULL,
                            i_upd timestamp(6) NOT NULL,
                            "name" varchar NOT NULL,
                            description varchar NULL,
                            CONSTRAINT compliance_profile_pkey PRIMARY KEY (uuid)
                        );
                
                        CREATE TABLE compliance_group (
                            "uuid" uuid NOT NULL,
                            "name" varchar NOT NULL,
                            kind varchar NOT NULL,
                            description text NULL,
                            decommissioned bool NULL,
                            connector_uuid uuid NULL,
                            CONSTRAINT compliance_group_pkey PRIMARY KEY (uuid),
                            CONSTRAINT compliance_group_to_connector FOREIGN KEY (connector_uuid) REFERENCES connector("uuid") ON DELETE CASCADE
                        );
                
                        CREATE TABLE compliance_rule (
                            "name" varchar NOT NULL,
                            "uuid" uuid NOT NULL,
                            kind varchar NOT NULL,
                            decommissioned bool NULL,
                            certificate_type varchar NOT NULL,
                            "attributes" text NULL,
                            description varchar NULL,
                            group_uuid uuid NULL,
                            connector_uuid uuid NULL,
                            CONSTRAINT compliance_rule_pkey PRIMARY KEY (uuid),
                            CONSTRAINT compliance_rule_to_compliance_group_key FOREIGN KEY (group_uuid) REFERENCES compliance_group("uuid"),
                            CONSTRAINT compliance_rule_to_connector_key FOREIGN KEY (connector_uuid) REFERENCES connector("uuid")
                        );
                
                        DROP TABLE compliance_profile_rule;
                        CREATE TABLE compliance_profile_rule (
                            "uuid" uuid NOT NULL,
                            i_author varchar NOT NULL,
                            i_cre timestamp(6) NOT NULL,
                            i_upd timestamp(6) NOT NULL,
                            "attributes" text NULL,
                            compliance_profile_uuid uuid NULL,
                            rule_uuid uuid NULL,
                            CONSTRAINT compliance_profile_rule_pkey PRIMARY KEY (uuid),
                            CONSTRAINT compliance_profile_rule_to_compliance_profile FOREIGN KEY (compliance_profile_uuid) REFERENCES compliance_profile("uuid"),
                            CONSTRAINT compliance_profile_rule_to_compliance_rule FOREIGN KEY (rule_uuid) REFERENCES compliance_rule("uuid")
                        );
                
                        CREATE TABLE ra_profile_2_compliance_profile (
                            ra_profile_uuid uuid NULL,
                            compliance_profile_uuid uuid NULL,
                            CONSTRAINT compliance_profile_to_mapping_key FOREIGN KEY (compliance_profile_uuid) REFERENCES compliance_profile("uuid") ON DELETE CASCADE
                        );
                
                        CREATE TABLE compliance_profile_2_compliance_group (
                        	profile_uuid uuid NULL,
                        	group_uuid uuid NULL,
                        	CONSTRAINT compliance_group_to_mapping_key FOREIGN KEY (group_uuid) REFERENCES compliance_group(uuid),
                        	CONSTRAINT compliance_profile_to_mapping_key FOREIGN KEY (profile_uuid) REFERENCES compliance_profile(uuid) ON DELETE CASCADE
                        );
                """;

        String sqlData = """
                        INSERT INTO certificate (uuid, i_author, i_cre, i_upd, subject_dn, public_key_algorithm, certificate_type, subject_type, validation_status, state, compliance_status, compliance_result)
                        VALUES (
                          '11111111-1111-1111-1111-111111111111', 'superadmin', '2025-01-01 00:00:00', '2025-01-01 00:00:00',
                          'CN=Test Certificate', 'RSA', 'X509', 'END_ENTITY', 'NOT_CHECKED', 'ISSUED',
                          'NOT_CHECKED', E'{"na":["40f084cc-ddc1-11ec-9d7f-34cff65c6ee3"], "nok":["40f08544-ddc1-11ec-9378-34cff65c6ee3"]}'
                        );
                
                        INSERT INTO connector (uuid, i_author, i_cre, i_upd, auth_type, name, status, url, version) VALUES ('80490584-ec68-48af-915e-9d2aed8ee471', 'superadmin', '2023-11-22 16:07:19.212517', '2023-11-22 16:07:19.212517', 'NONE', 'X509-Compliance-Provider', 'CONNECTED', 'http://localhost:8250', 'V1');
                        INSERT INTO compliance_profile (uuid, i_author, i_cre, i_upd, name, description) VALUES ('44ce3ecf-ecd5-43cc-a836-8171b42ca2af', 'superadmin', '2023-11-30 16:33:30.855932', '2023-11-30 16:33:30.855932', 'BasicComplianceProfile', '');
                        INSERT INTO ra_profile_2_compliance_profile (ra_profile_uuid, compliance_profile_uuid) VALUES ('9e834b25-3c44-4251-8745-3bd8c0d99ff4', '44ce3ecf-ecd5-43cc-a836-8171b42ca2af');
                
                        INSERT INTO compliance_group (uuid, name, kind, description, decommissioned, connector_uuid) VALUES ('52350996-ddb2-11ec-9d64-0242ac120002', 'Apple''s CT Policy', 'x509', 'https://support.apple.com/en-us/HT205280#:~:text=Apple''s%20policy%20requires%20at%20least,extension%20or%20OCSP%20Stapling%3B%20or', false, '80490584-ec68-48af-915e-9d2aed8ee471');
                        INSERT INTO compliance_group (uuid, name, kind, description, decommissioned, connector_uuid) VALUES ('52350df6-ddb2-11ec-9d64-0242ac120002', 'Mozilla''s PKI Policy', 'x509', 'https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/', false, '80490584-ec68-48af-915e-9d2aed8ee471');
                
                        INSERT INTO compliance_profile_2_compliance_group (profile_uuid, group_uuid) VALUES ('44ce3ecf-ecd5-43cc-a836-8171b42ca2af', '52350996-ddb2-11ec-9d64-0242ac120002');
                        INSERT INTO compliance_profile_2_compliance_group (profile_uuid, group_uuid) VALUES ('44ce3ecf-ecd5-43cc-a836-8171b42ca2af', '52350df6-ddb2-11ec-9d64-0242ac120002');
                
                        INSERT INTO compliance_rule (name, uuid, kind, decommissioned, certificate_type, description, group_uuid, connector_uuid) VALUES ('e_mp_modulus_must_be_2048_bits_or_more', '40f08544-ddc1-11ec-9378-34cff65c6ee3', 'x509', false, 'X509', 'RSA keys must have modulus size of at least 2048 bits', '52350df6-ddb2-11ec-9d64-0242ac120002', '80490584-ec68-48af-915e-9d2aed8ee471');
                        INSERT INTO compliance_rule (name, uuid, kind, decommissioned, certificate_type, description, group_uuid, connector_uuid) VALUES ('e_algorithm_identifier_improper_encoding', '40f084cc-ddc1-11ec-9d7f-34cff65c6ee3', 'x509', false, 'X509', 'Encoded AlgorithmObjectIdentifier objects inside a SubjectPublicKeyInfo field MUST comply with specified byte sequences.', NULL, '80490584-ec68-48af-915e-9d2aed8ee471');
                        INSERT INTO compliance_rule (name,uuid,kind,decommissioned,certificate_type,"attributes",description,group_uuid,connector_uuid) VALUES
                             ('cus_public_key_algorithm','6dcf0d44-ddc3-11ec-9d64-0242ac120002'::uuid,'x509',false,'X509','[{"uuid":"8b2a6051-7c67-4b75-a224-c3edb55b0890","name":"condition","content":[{"reference":"Equals","data":"Equals"},{"reference":"NotEquals","data":"NotEquals"}],"type":"data","contentType":"string","properties":{"label":"Condition","visible":true,"group":null,"required":true,"readOnly":false,"list":true,"multiSelect":false}},{"uuid":"8b2a6051-7c67-4b75-a224-c3edb55b0891","name":"algorithm","content":[{"reference":"RSA","data":"RSA"},{"reference":"DSA","data":"DSA"},{"reference":"ECDSA","data":"ECDSA"}],"type":"data","contentType":"string","properties":{"label":"Public Key Algorithm","visible":true,"group":null,"required":true,"readOnly":false,"list":true,"multiSelect":true}}]','Public key algorithm of the certificate',NULL,'80490584-ec68-48af-915e-9d2aed8ee471'::uuid),
                             ('cus_key_length','7ed00480-e706-11ec-8fea-0242ac120002'::uuid,'x509',false,'X509','[{"uuid":"7ed00782-e706-11ec-8fea-0242ac120002","name":"condition","content":[{"reference":"Equals","data":"Equals"},{"reference":"NotEquals","data":"NotEquals"},{"reference":"Greater","data":"Greater"},{"reference":"Lesser","data":"Lesser"}],"type":"data","contentType":"string","properties":{"label":"Condition","visible":true,"group":null,"required":true,"readOnly":false,"list":true,"multiSelect":false}},{"uuid":"7ed00886-e706-11ec-8fea-0242ac120002","name":"length","type":"data","contentType":"integer","properties":{"label":"Key Length","visible":true,"group":null,"required":true,"readOnly":false,"list":false,"multiSelect":false}}]','Public Key length of the certificate should be',NULL,'80490584-ec68-48af-915e-9d2aed8ee471'::uuid);
                
                        INSERT INTO compliance_profile_rule (uuid, i_author, i_cre, i_upd, compliance_profile_uuid, rule_uuid) VALUES ('cc9a2fc0-dcc7-49a2-ad57-ce3559a3ee71', 'superadmin', '2023-11-30 16:34:32.338669', '2023-11-30 16:34:32.338669', '44ce3ecf-ecd5-43cc-a836-8171b42ca2af', '40f08544-ddc1-11ec-9378-34cff65c6ee3');
                        INSERT INTO compliance_profile_rule (uuid, i_author, i_cre, i_upd, compliance_profile_uuid, rule_uuid) VALUES ('ab5e89fd-d6a8-460c-a397-c173f6043aed', 'superadmin', '2025-07-17 21:10:15.965651', '2025-07-17 21:10:15.965651', '44ce3ecf-ecd5-43cc-a836-8171b42ca2af', '40f084cc-ddc1-11ec-9d7f-34cff65c6ee3');
                        INSERT INTO compliance_profile_rule (uuid,i_author,i_cre,i_upd,"attributes",compliance_profile_uuid,rule_uuid) VALUES
                        	 ('1a3dbb1e-76e7-4814-9610-772400e85115'::uuid,'adminadmin','2022-10-17 14:26:13.871','2022-10-17 14:26:13.871','[{"content":[{"reference":"Equals","data":"Equals"}]},{"name":"algorithm","content":[{"reference":"RSA","data":"RSA"}]}]','44ce3ecf-ecd5-43cc-a836-8171b42ca2af'::uuid,'40f08544-ddc1-11ec-9378-34cff65c6ee3'::uuid),
                        	 ('5645599d-8017-432f-ad42-8abba2b0b528'::uuid,'adminadmin','2022-10-17 14:26:13.871','2022-10-17 14:26:13.871','[{"name":"condition","content":[{"reference":"Equals","data":"Equals"}]},{"name":"algorithm","content":[{"reference":"RSA","data":"RSA"}]}]','44ce3ecf-ecd5-43cc-a836-8171b42ca2af'::uuid,'40f08544-ddc1-11ec-9378-34cff65c6ee3'::uuid),
                        	 ('b5025c93-9cb0-424e-8258-01a092c2d6a8'::uuid,'adminadmin','2022-10-17 14:26:13.871','2022-10-17 14:26:13.871','[{"name":"condition","content":[{"reference":"Equals","data":"Equals"}]},{"name":"algorithm","content":[{"reference":"RSA","data":"RSA"}]}]','44ce3ecf-ecd5-43cc-a836-8171b42ca2af'::uuid,'6dcf0d44-ddc3-11ec-9d64-0242ac120002'::uuid),
                        	 ('5388720e-0146-4f2d-8ca7-a1dff7e9fad7'::uuid,'adminadmin','2023-06-21 13:57:46.127','2023-06-21 13:57:46.127','[{"uuid":"7ed00782-e706-11ec-8fea-0242ac120002","name":"condition","contentType":"string","content":[{"reference":"Greater","data":"Greater"}]},{"uuid":"7ed00886-e706-11ec-8fea-0242ac120002","name":"length","contentType":"integer","content":[{"reference":null,"data":"2050"}]}]','44ce3ecf-ecd5-43cc-a836-8171b42ca2af'::uuid,'7ed00480-e706-11ec-8fea-0242ac120002'::uuid);
                
                """;

        try (Statement statement = context.getConnection().createStatement()) {
            statement.execute(sqlStructure);
            statement.execute(sqlData);
        }
    }

    private void assertNewFunctionGroupAndEndpointsExists(Connection conn) throws SQLException {
        try (Statement statement = conn.createStatement();
             ResultSet resultSet = statement.executeQuery("SELECT * FROM function_group WHERE code = 'COMPLIANCE_PROVIDER_V2'")) {
            Assertions.assertTrue(resultSet.next());
        }

        try (Statement statement = conn.createStatement();
             ResultSet resultSet = statement.executeQuery("SELECT * FROM endpoint WHERE function_group_uuid IS NOT NULL")) {
            Assertions.assertTrue(resultSet.next());
        }
    }

    private void assertMigratedDataPresence(Connection conn) throws Exception {
        // verify RA profile associations were migrated
        try (Statement statement = conn.createStatement();
             ResultSet resultSet = statement.executeQuery("SELECT * FROM compliance_profile_association WHERE resource = 'RA_PROFILE'")) {
            Assertions.assertTrue(resultSet.next());
            Assertions.assertEquals("9e834b25-3c44-4251-8745-3bd8c0d99ff4", resultSet.getObject("object_uuid").toString());
        }

        // verify compliance profile group association was migrated
        try (Statement statement = conn.createStatement();
             ResultSet resultSet = statement.executeQuery("SELECT * FROM compliance_profile_rule WHERE compliance_group_uuid = '52350996-ddb2-11ec-9d64-0242ac120002'")) {
            Assertions.assertTrue(resultSet.next());
            Assertions.assertEquals(UUID.fromString("44ce3ecf-ecd5-43cc-a836-8171b42ca2af"), resultSet.getObject("compliance_profile_uuid", UUID.class));
        }

        // verify nullified attributes in compliance profile rules
        try (Statement statement = conn.createStatement();
             ResultSet resultSet = statement.executeQuery("SELECT attributes FROM compliance_profile_rule WHERE uuid = '1a3dbb1e-76e7-4814-9610-772400e85115' OR uuid = '5645599d-8017-432f-ad42-8abba2b0b528'")) {

            int count = 0;
            while (resultSet.next()) {
                Assertions.assertNull(resultSet.getString("attributes"));
                count++;
            }
            Assertions.assertEquals(2, count);
        }

        try (Statement statement = conn.createStatement();
             ResultSet resultSet = statement.executeQuery("SELECT attributes FROM compliance_profile_rule WHERE uuid = 'b5025c93-9cb0-424e-8258-01a092c2d6a8'")) {
            Assertions.assertTrue(resultSet.next());

            String ruleAttributesJson = resultSet.getString("attributes");
            Assertions.assertNotNull(ruleAttributesJson);
            List<RequestAttributeV2> profileRuleAttributes = objectMapper.readValue(ruleAttributesJson, new TypeReference<>() {
            });

            Assertions.assertEquals(2, profileRuleAttributes.size());
            for (RequestAttributeV2 profileRuleAttribute : profileRuleAttributes) {
                if (profileRuleAttribute.getName().equals("condition")) {
                    Assertions.assertEquals(1, profileRuleAttribute.getContent().size());
                    Assertions.assertEquals("Equals", profileRuleAttribute.getContent().getFirst().getData());
                    Assertions.assertEquals("8b2a6051-7c67-4b75-a224-c3edb55b0890", profileRuleAttribute.getUuid().toString());
                    Assertions.assertEquals(AttributeContentType.STRING, profileRuleAttribute.getContentType());
                } else if (profileRuleAttribute.getName().equals("algorithm")) {
                    Assertions.assertEquals(1, profileRuleAttribute.getContent().size());
                    Assertions.assertEquals("RSA", profileRuleAttribute.getContent().getFirst().getData());
                    Assertions.assertEquals("8b2a6051-7c67-4b75-a224-c3edb55b0891", profileRuleAttribute.getUuid().toString());
                    Assertions.assertEquals(AttributeContentType.STRING, profileRuleAttribute.getContentType());
                } else {
                    Assertions.fail("Unexpected attribute name: " + profileRuleAttribute.getName());
                }
            }
        }

        // verify certificate compliance_result was migrated to new JSON structure
        try (Statement statement = conn.createStatement();
             ResultSet rs = statement.executeQuery("SELECT compliance_result FROM certificate WHERE uuid = '11111111-1111-1111-1111-111111111111'")) {
            Assertions.assertTrue(rs.next(), "migrated certificate row must exist");
            String complianceResultJson = rs.getString("compliance_result");
            Assertions.assertNotNull(complianceResultJson, "compliance_result must not be null after migration");

            ComplianceResultDto resultDto = objectMapper.readValue(complianceResultJson, ComplianceResultDto.class);

            Assertions.assertNotNull(resultDto);
            Assertions.assertEquals(ComplianceStatus.NOT_CHECKED, resultDto.getStatus(), "status should be preserved in migrated JSON");
            Assertions.assertNotNull(resultDto.getTimestamp());
            Assertions.assertNull(resultDto.getInternalRules());
            Assertions.assertNotNull(resultDto.getProviderRules());
            Assertions.assertEquals(1, resultDto.getProviderRules().size(), "There should be rules from exactly one provider");

            var providerRules = resultDto.getProviderRules().getFirst();
            Assertions.assertEquals("80490584-ec68-48af-915e-9d2aed8ee471", providerRules.getConnectorUuid().toString(), "connector UUID should match");
            Assertions.assertEquals("x509", providerRules.getKind(), "kind should match");
            Assertions.assertEquals(1, providerRules.getNotApplicable().size(), "notApplicable rules should have 1 entry");
            Assertions.assertEquals("40f084cc-ddc1-11ec-9d7f-34cff65c6ee3", providerRules.getNotApplicable().stream().findFirst().orElseThrow().toString(), "notApplicable rule UUID should match");
            Assertions.assertEquals(1, providerRules.getNotCompliant().size(), "notCompliant rules should have 1 entry");
            Assertions.assertEquals("40f08544-ddc1-11ec-9378-34cff65c6ee3", providerRules.getNotCompliant().stream().findFirst().orElseThrow().toString(), "notCompliant rule UUID should match");
        }
    }
}

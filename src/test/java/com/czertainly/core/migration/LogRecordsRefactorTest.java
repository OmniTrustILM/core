package com.czertainly.core.migration;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.enums.*;
import com.czertainly.api.model.core.logging.enums.Module;
import com.czertainly.api.model.core.logging.records.LogRecord;
import com.czertainly.api.model.core.logging.records.ResourceObjectIdentity;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.AuditLogRepository;
import db.migration.V202509191412__LogRecordsRefactor;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import javax.sql.DataSource;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.OffsetDateTime;
import java.util.List;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LogRecordsRefactorTest extends BaseMigrationTest {

    @Autowired
    DataSource dataSource;

    @Autowired
    AuditLogRepository auditLogRepository;

    private static final String NULL_RESOURCE = """
            {
              "actor": {
                "name": "adminadmin",
                "type": "user",
                "uuid": "42633830-158d-4a45-b2a0-799b770ccf9d",
                "authMethod": "certificate"
              },
              "module": "core",
              "source": {
                "path": "/api/v1/notifications",
                "method": "GET",
                "ipAddress": "0:0:0:0:0:0:0:1",
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
                "contentType": null
              },
              "audited": true,
              "message": null,
              "version": "1.0",
              "resource": null,
              "operation": "list",
              "operationData": null,
              "additionalData": {
                "request": {
                  "unread": true,
                  "pageNumber": 1,
                  "itemsPerPage": 10
                }
              },
              "operationResult": "success",
              "affiliatedResource": {
                  "type": "notifications",
                    "names": null,
                    "uuids": null
               }
            }
            """;

    private static final String NULL_AFFILIATED_RESOURCE = """
              {
                "actor": {
                  "name": "adminadmin",
                  "type": "user",
                  "uuid": "42633830-158d-4a45-b2a0-799b770ccf9d",
                  "authMethod": "certificate"
                },
                "module": "core",
                "source": {
                  "path": "/api/v1/notifications",
                  "method": "GET",
                  "ipAddress": "0:0:0:0:0:0:0:1",
                  "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
                  "contentType": null
                },
                "audited": true,
                "message": null,
                "version": "1.0",
                "resource": {
                  "type": "notifications",
                  "names": ["name1"],
                  "uuids": null
                },
                "operation": "list",
                "operationData": null,
                "additionalData": {
                  "request": {
                    "unread": true,
                    "pageNumber": 1,
                    "itemsPerPage": 10
                  }
                },
                "operationResult": "success",
                "affiliatedResource": null
              }
            """;

    private static final String NULL_BOTH_RESOURCES = """
              {
                "actor": {
                  "name": "adminadmin",
                  "type": "user",
                  "uuid": "42633830-158d-4a45-b2a0-799b770ccf9d",
                  "authMethod": "certificate"
                },
                "module": "core",
                "source": {
                  "path": "/api/v1/notifications",
                  "method": "GET",
                  "ipAddress": "0:0:0:0:0:0:0:1",
                  "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
                  "contentType": null
                },
                "audited": true,
                "message": null,
                "version": "1.0",
                "resource": null,
                "operation": "list",
                "operationData": null,
                "additionalData": {
                  "request": {
                    "unread": true,
                    "pageNumber": 1,
                    "itemsPerPage": 10
                  }
                },
                "operationResult": "success",
                "affiliatedResource": null
              }
            """;

    private static final String ONE_NAME_TWO_UUIDS = """
              {
                "actor": {
                  "name": "adminadmin",
                  "type": "user",
                  "uuid": "42633830-158d-4a45-b2a0-799b770ccf9d",
                  "authMethod": "certificate"
                },
                "module": "core",
                "source": {
                  "path": "/api/v1/notifications",
                  "method": "GET",
                  "ipAddress": "0:0:0:0:0:0:0:1",
                  "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
                  "contentType": null
                },
                "audited": true,
                "message": null,
                "version": "1.0",
                "resource": {
                  "type": "notifications",
                  "names": ["name1"],
                  "uuids": ["6057ad37-2c27-42d6-a232-0622b5dcc10d","6057ad37-2c27-42d6-a232-0622b5dcc102"]
                },
                "operation": "list",
                "operationData": null,
                "additionalData": {
                  "request": {
                    "unread": true,
                    "pageNumber": 1,
                    "itemsPerPage": 10
                  }
                },
                "operationResult": "success",
                "affiliatedResource": null
              }
            """;

    private static final String TWO_NAMES_TWO_UUIDS = """
              {
                "actor": {
                  "name": "adminadmin",
                  "type": "user",
                  "uuid": "42633830-158d-4a45-b2a0-799b770ccf9d",
                  "authMethod": "certificate"
                },
                "module": "core",
                "source": {
                  "path": "/api/v1/notifications",
                  "method": "GET",
                  "ipAddress": "0:0:0:0:0:0:0:1",
                  "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
                  "contentType": null
                },
                "audited": true,
                "message": null,
                "version": "1.0",
                "resource": {
                  "type": "notifications",
                  "names": ["name1", "name2"],
                  "uuids": ["6057ad37-2c27-42d6-a232-0622b5dcc10d","6057ad37-2c27-42d6-a232-0622b5dcc102"]
                },
                "operation": "list",
                "operationData": null,
                "additionalData": {
                  "request": {
                    "unread": true,
                    "pageNumber": 1,
                    "itemsPerPage": 10
                  }
                },
                "operationResult": "success",
                "affiliatedResource": null
              }
            """;

    private static final String TWO_NAMES_ONE_UUID = """
              {
                "actor": {
                  "name": "adminadmin",
                  "type": "user",
                  "uuid": "42633830-158d-4a45-b2a0-799b770ccf9d",
                  "authMethod": "certificate"
                },
                "module": "core",
                "source": {
                  "path": "/api/v1/notifications",
                  "method": "GET",
                  "ipAddress": "0:0:0:0:0:0:0:1",
                  "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
                  "contentType": null
                },
                "audited": true,
                "message": null,
                "version": "1.0",
                "resource": {
                  "type": "notifications",
                  "names": ["name1", "name2"],
                  "uuids": ["6057ad37-2c27-42d6-a232-0622b5dcc10d"]
                },
                "operation": "list",
                "operationData": null,
                "additionalData": {
                  "request": {
                    "unread": true,
                    "pageNumber": 1,
                    "itemsPerPage": 10
                  }
                },
                "operationResult": "success",
                "affiliatedResource": {"names": null,
                  "uuids": null}
              }
            """;


    AuditLog nullResource = new AuditLog();
    AuditLog nullAffiliatedResource = new AuditLog();
    AuditLog nullBothResources = new AuditLog();
    AuditLog oneNameTwoUuids = new AuditLog();
    AuditLog twoNamesOneUuid = new AuditLog();
    AuditLog twoNamesTwoUuids = new AuditLog();

    @Test
    void testMigration() throws Exception {
        List<AuditLog> auditLogs = List.of(nullResource, nullAffiliatedResource, nullBothResources, oneNameTwoUuids, twoNamesTwoUuids, twoNamesOneUuid);
        for (AuditLog auditLog : auditLogs) setNotNullFields(auditLog);
        auditLogRepository.saveAll(auditLogs);

        Context context = Mockito.mock(Context.class);
        when(context.getConnection()).thenReturn(dataSource.getConnection());
        simulateOldEnvironment(context);

        V202509191412__LogRecordsRefactor migration = new V202509191412__LogRecordsRefactor();
        migration.migrate(context);

        // Reload records after migration
        nullResource = auditLogRepository.findById(nullResource.getId()).orElseThrow();
        nullAffiliatedResource = auditLogRepository.findById(nullAffiliatedResource.getId()).orElseThrow();
        nullBothResources = auditLogRepository.findById(nullBothResources.getId()).orElseThrow();
        oneNameTwoUuids = auditLogRepository.findById(oneNameTwoUuids.getId()).orElseThrow();
        twoNamesOneUuid = auditLogRepository.findById(twoNamesOneUuid.getId()).orElseThrow();
        twoNamesTwoUuids = auditLogRepository.findById(twoNamesTwoUuids.getId()).orElseThrow();

        // --- NULL RESOURCE ---
        Assertions.assertNull(nullResource.getLogRecord().resource());
        Assertions.assertNotNull(nullResource.getLogRecord().affiliatedResource());
        Assertions.assertNull(nullResource.getLogRecord().affiliatedResource().objects());

        // --- NULL AFFILIATED RESOURCE ---
        Assertions.assertNotNull(nullAffiliatedResource.getLogRecord().resource());
        Assertions.assertEquals(1, nullAffiliatedResource.getLogRecord().resource().objects().size());
        ResourceObjectIdentity onlyObject = nullAffiliatedResource.getLogRecord().resource().objects().getFirst();
        Assertions.assertEquals("name1", onlyObject.name());
        Assertions.assertNull(onlyObject.uuid());
        Assertions.assertNull(nullAffiliatedResource.getLogRecord().affiliatedResource());

        // --- NULL BOTH RESOURCES ---
        Assertions.assertNull(nullBothResources.getLogRecord().resource());
        Assertions.assertNull(nullBothResources.getLogRecord().affiliatedResource());

        // --- ONE NAME, TWO UUIDS ---
        Assertions.assertEquals(2, oneNameTwoUuids.getLogRecord().resource().objects().size());
        // verify first object
        List<ResourceObjectIdentity> objectsOne = oneNameTwoUuids.getLogRecord().resource().objects();
        Assertions.assertEquals("name1", objectsOne.get(0).name());
        Assertions.assertEquals("6057ad37-2c27-42d6-a232-0622b5dcc10d", objectsOne.get(0).uuid().toString());
        Assertions.assertNull(objectsOne.get(1).name());
        Assertions.assertEquals("6057ad37-2c27-42d6-a232-0622b5dcc102", objectsOne.get(1).uuid().toString());

        // --- TWO NAMES, ONE UUID ---
        Assertions.assertEquals(2, twoNamesOneUuid.getLogRecord().resource().objects().size());
        List<ResourceObjectIdentity> objectsTwo = twoNamesOneUuid.getLogRecord().resource().objects();
        Assertions.assertEquals("name1", objectsTwo.get(0).name());
        Assertions.assertEquals("6057ad37-2c27-42d6-a232-0622b5dcc10d", objectsTwo.get(0).uuid().toString());
        Assertions.assertEquals("name2", objectsTwo.get(1).name());
        Assertions.assertNull(objectsTwo.get(1).uuid());

        // --- TWO NAMES, TWO UUIDS ---
        Assertions.assertEquals(2, twoNamesTwoUuids.getLogRecord().resource().objects().size());
        List<ResourceObjectIdentity> objectsThree = twoNamesTwoUuids.getLogRecord().resource().objects();
        Assertions.assertEquals("name1", objectsThree.get(0).name());
        Assertions.assertEquals("6057ad37-2c27-42d6-a232-0622b5dcc10d", objectsThree.get(0).uuid().toString());
        Assertions.assertEquals("name2", objectsThree.get(1).name());
        Assertions.assertEquals("6057ad37-2c27-42d6-a232-0622b5dcc102", objectsThree.get(1).uuid().toString());

    }

    private void simulateOldEnvironment(Context context) throws SQLException {
        try (Statement alterStatement = context.getConnection().createStatement();
             Statement insertStatement = context.getConnection().createStatement()) {
            alterStatement.execute("ALTER TABLE audit_log DROP COLUMN timestamp;");
            insertStatement.execute("""
                    UPDATE audit_log SET log_record='%s' WHERE id='%s'
                    """.formatted(NULL_RESOURCE, nullResource.getId()));
            insertStatement.execute("""
                    UPDATE audit_log SET log_record='%s' WHERE id='%s'
                    """.formatted(NULL_AFFILIATED_RESOURCE, nullAffiliatedResource.getId()));
            insertStatement.execute("""
                    UPDATE audit_log SET log_record='%s' WHERE id='%s'
                    """.formatted(NULL_BOTH_RESOURCES, nullBothResources.getId()));
            insertStatement.execute("""
                    UPDATE audit_log SET log_record='%s' WHERE id='%s'
                    """.formatted(ONE_NAME_TWO_UUIDS, oneNameTwoUuids.getId()));
            insertStatement.execute("""
                    UPDATE audit_log SET log_record='%s' WHERE id='%s'
                    """.formatted(TWO_NAMES_ONE_UUID, twoNamesOneUuid.getId()));
            insertStatement.execute("""
                    UPDATE audit_log SET log_record='%s' WHERE id='%s'
                    """.formatted(TWO_NAMES_TWO_UUIDS, twoNamesTwoUuids.getId()));
        }
    }

    private void setNotNullFields(AuditLog entity) {
        entity.setVersion("1.0");
        entity.setModule(Module.AUTH);
        entity.setActorType(ActorType.USER);
        entity.setActorAuthMethod(AuthMethod.NONE);
        entity.setResource(Resource.CERTIFICATE);
        entity.setOperation(Operation.LOGOUT);
        entity.setOperationResult(OperationResult.FAILURE);
        entity.setTimestamp(OffsetDateTime.now());

        LogRecord logRecord = LogRecord.builder().build();
        entity.setLogRecord(logRecord);

    }
}

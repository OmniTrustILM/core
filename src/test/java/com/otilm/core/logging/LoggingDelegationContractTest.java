package com.otilm.core.logging;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.logging.records.ActorRecord;
import com.otilm.api.model.core.logging.records.DelegateRecord;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.logging.records.ResourceRecord;
import com.otilm.api.model.core.logging.records.SourceRecord;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.io.InputStream;
import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import static org.assertj.core.api.Assertions.assertThat;

class LoggingDelegationContractTest {

    private static final ObjectMapper MAPPER = ObjectMapperFactory.auditLog();

    @Test
    void newlyEmittedRecordsValidateAgainstSchema12() throws Exception {
        LoggerWrapper logger = new LoggerWrapper(getClass(), Module.AUTH, Resource.USER);
        LogRecord emitted = logger
                .buildLogRecord(true, null, null, List.of(), Operation.DETAIL, OperationResult.SUCCESS, null, null,
                        null);

        assertThat(emitted.version()).isEqualTo("1.2");
        assertThat(schema("1.2").validate(MAPPER.valueToTree(emitted))).isEmpty();
    }

    @Test
    void schema12AcceptsTheImmediateDelegateWithOrWithoutItsDistinctSubject() throws Exception {
        for (DelegateRecord delegate : List
                .of(new DelegateRecord("automation-client", "service-account-id"),
                        new DelegateRecord("automation-client", null))) {
            JsonNode auditRecord = MAPPER.valueToTree(auditRecord("1.2", delegate));
            assertThat(schema("1.2").validate(auditRecord)).isEmpty();
        }
    }

    @Test
    void directRecordsRemainValidAgainstBothSchemas() throws Exception {
        JsonNode legacy = MAPPER.valueToTree(auditRecord("1.1", null));
        JsonNode direct = MAPPER.valueToTree(auditRecord("1.2", null));

        assertThat(legacy.path("actor").has("delegate")).isFalse();
        assertThat(schema("1.1").validate(legacy)).isEmpty();
        assertThat(schema("1.2").validate(direct)).isEmpty();
    }

    @Test
    void schema12RequiresTheDelegateIdentifierAndKeepsUnknownActorMembersInvalid() throws Exception {
        ObjectNode missingIdentifier = MAPPER.valueToTree(auditRecord("1.2", new DelegateRecord("client", "subject")));
        ((ObjectNode) missingIdentifier.path("actor").path("delegate")).remove("identifier");
        ObjectNode unknownMember = MAPPER.valueToTree(auditRecord("1.2", null));
        ((ObjectNode) unknownMember.path("actor")).put("unexpected", "value");

        assertThat(schema("1.2").validate(missingIdentifier)).isNotEmpty();
        assertThat(schema("1.2").validate(unknownMember)).isNotEmpty();
    }

    @Test
    void schema11StillRejectsTheDelegateMember() throws Exception {
        assertThat(schema("1.1").validate(MAPPER.valueToTree(auditRecord("1.2", new DelegateRecord("client", null)))))
                .isNotEmpty();
    }

    @Test
    void anOlderJmsReaderKeepsTheUserAndAcceptsTheUnrecognizedDelegate() throws Exception {
        ObjectMapper jms = ObjectMapperFactory.jmsMessage(Jackson2ObjectMapperBuilder.json());
        AuditLogMessage message = new AuditLogMessage(auditRecord("1.2", new DelegateRecord("client", "subject")),
                AuditLogOutput.DATABASE);

        LegacyAuditLogMessage received = jms.readValue(jms.writeValueAsBytes(message), LegacyAuditLogMessage.class);

        assertThat(received.auditLogOutput()).isEqualTo(AuditLogOutput.DATABASE);
        assertThat(received.logRecord().version()).isEqualTo("1.2");
        assertThat(received.logRecord().actor())
                .isEqualTo(new LegacyActorRecord(ActorType.USER, AuthMethod.TOKEN,
                        UUID.fromString("b2cba93a-7cd6-4a2f-a050-6631c3886059"), "alice"));
        assertThat(received.logRecord().operation()).isEqualTo(Operation.DETAIL);
    }

    private static JsonSchema schema(String version) throws Exception {
        try (InputStream resource = LoggingDelegationContractTest.class
                .getResourceAsStream("/log-schemas/LogRecord-" + version + ".json")) {
            assertThat(resource).as("published log schema %s", version).isNotNull();
            return JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012).getSchema(MAPPER.readTree(resource));
        }
    }

    private static LogRecord auditRecord(String version, DelegateRecord delegate) {
        return LogRecord
                .builder()
                .version(version)
                .audited(true)
                .module(Module.AUTH)
                .actor(new ActorRecord(ActorType.USER, AuthMethod.TOKEN,
                        UUID.fromString("b2cba93a-7cd6-4a2f-a050-6631c3886059"), "alice", delegate))
                .resource(new ResourceRecord(Resource.USER, List.of()))
                .operation(Operation.DETAIL)
                .operationResult(OperationResult.SUCCESS)
                .timestamp(OffsetDateTime.parse("2026-10-24T10:15:30Z"))
                .build();
    }

    private record LegacyAuditLogMessage(LegacyLogRecord logRecord, AuditLogOutput auditLogOutput) {
    }

    private record LegacyActorRecord(ActorType type, AuthMethod authMethod, UUID uuid, String name) {
    }

    private record LegacyLogRecord(String version, boolean audited, Module module, LegacyActorRecord actor,
            SourceRecord source, ResourceRecord resource, ResourceRecord affiliatedResource, Operation operation,
            OperationResult operationResult, String message, Serializable operationData,
            Map<String, Object> additionalData, OffsetDateTime timestamp) {
    }
}

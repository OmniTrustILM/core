package com.czertainly.core.signing.record;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.core.signing.signingrecord.SigningRecordDto;
import com.czertainly.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.czertainly.core.model.signing.SigningProfileModel;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.SigningRecordService;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static com.czertainly.core.model.signing.SigningProfileModelBuilder.aSigningProfile;
import static com.czertainly.core.model.signing.SigningRecordPolicyModelBuilder.notRecording;
import static com.czertainly.core.model.signing.SigningRecordPolicyModelBuilder.recordingEverything;
import static com.czertainly.core.signing.record.SigningRecordInputBuilder.aSigningRecordInput;
import static com.czertainly.core.util.SearchRequestDtoBuilder.aSearchRequest;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ImmediateSigningRecordWriterTest extends BaseSpringBootTest {

    @Autowired
    private ImmediateSigningRecordWriter writer;

    @Autowired
    private SigningRecordService signingRecordService;

    @Test
    void persistsAllRecordableContent_whenEveryToggleEnabled() throws NotFoundException {
        // given
        SigningProfileModel<?, ?> signingProfile = aSigningProfile()
                .recordPolicy(recordingEverything().build())
                .build();
        SigningRecordInput input = aSigningRecordInput()
                .signingProfile(signingProfile)
                .requestMetadataJson("{ \"foo\": \"bar\" }")
                .signature("the-signature".getBytes(UTF_8))
                .signedDocument("the-signed-document".getBytes(UTF_8))
                .dtbs("the-data-to-be-signed".getBytes(UTF_8))
                .build();

        // when
        writer.record(input);

        // then
        List<SigningRecordListDto> all = signingRecordService
                .listSigningRecords(aSearchRequest().build(), SecurityFilter.create())
                .getItems();
        assertEquals(1, all.size());

        SigningRecordDto record = signingRecordService
                .getSigningRecord(SecuredUUID.fromString(all.getFirst().getUuid()));
        assertEquals("{ \"foo\": \"bar\" }", record.getRequestMetadataJson());
        assertEquals("the-signature", new String(record.getSignatureValue(), UTF_8));
        assertEquals("the-signed-document", new String(record.getSignedDocument(), UTF_8));
        assertEquals("the-data-to-be-signed", new String(record.getDtbs(), UTF_8));
    }

    @Test
    void noToggleEnabledIsNoOp() {
        // given
        SigningProfileModel<?, ?> signingProfile = aSigningProfile()
                .recordPolicy(notRecording().build())
                .build();
        SigningRecordInput input = aSigningRecordInput().signingProfile(signingProfile).build();

        // when
        writer.record(input);

        // then
        List<SigningRecordListDto> all = signingRecordService
                .listSigningRecords(aSearchRequest().build(), SecurityFilter.create())
                .getItems();
        assertEquals(0, all.size());
    }
}

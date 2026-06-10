package com.czertainly.core.security.authz;

import com.otilm.api.exception.ValidationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class SecuredUUIDTest {

    @Test
    void fromString_returnsNull_whenInputIsNull() {
        // when
        var result = SecuredUUID.fromString(null);

        // then
        assertNull(result);
    }

    @Test
    void fromString_wrapsUUID_forValidUuidString() {
        // given
        var uuid = UUID.randomUUID();

        // when
        var result = SecuredUUID.fromString(uuid.toString());

        // then
        assertEquals(uuid, result.getValue());
    }

    @Test
    void fromString_throwsValidationException_forInvalidUuidString() {
        // given
        var invalidUuid = "not-a-uuid";

        // when
        Executable transform = () -> SecuredUUID.fromString(invalidUuid);

        // then
        assertThrows(ValidationException.class, transform);
    }

    @Test
    void fromUUID_wrapsUUID() {
        // given
        var uuid = UUID.randomUUID();

        // when
        var result = SecuredUUID.fromUUID(uuid);

        // then
        assertEquals(uuid, result.getValue());
    }

    @Test
    void fromList_convertsAllStringsToSecuredUUIDs() {
        // given
        var uuid1 = UUID.randomUUID();
        var uuid2 = UUID.randomUUID();

        // when
        var result = SecuredUUID.fromList(List.of(uuid1.toString(), uuid2.toString()));

        // then
        assertEquals(List.of(uuid1, uuid2), result.stream().map(SecuredUUID::getValue).toList());
    }

    @Test
    void asList_convertsVarargsStringsToSecuredUUIDs() {
        // given
        var uuid1 = UUID.randomUUID();
        var uuid2 = UUID.randomUUID();

        // when
        var result = SecuredUUID.asList(uuid1.toString(), uuid2.toString());

        // then
        assertEquals(List.of(uuid1, uuid2), result.stream().map(SecuredUUID::getValue).toList());
    }

    @Test
    void fromUuidList_convertsAllUUIDsToSecuredUUIDs() {
        // given
        var uuid1 = UUID.randomUUID();
        var uuid2 = UUID.randomUUID();

        // when
        var result = SecuredUUID.fromUuidList(List.of(uuid1, uuid2));

        // then
        assertEquals(List.of(uuid1, uuid2), result.stream().map(SecuredUUID::getValue).toList());
    }

    @Test
    void getValue_returnsWrappedUUID() {
        // given
        var uuid = UUID.randomUUID();
        var securedUUID = SecuredUUID.fromUUID(uuid);

        // when
        var result = securedUUID.getValue();

        // then
        assertEquals(uuid, result);
    }

    @Test
    void toString_returnsUUIDString() {
        // given
        var uuid = UUID.randomUUID();
        var securedUUID = SecuredUUID.fromUUID(uuid);

        // when
        var result = securedUUID.toString();

        // then
        assertEquals(uuid.toString(), result);
    }

    @Test
    void toString_returnsNullSentinel_whenWrappedValueIsNull() {
        // given
        var securedUUID = SecuredUUID.fromUUID(null);

        // when
        var result = securedUUID.toString();

        // then
        assertEquals("SecuredUUID[null]", result);
    }
}

package com.otilm.core.model;

import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static com.otilm.core.util.builders.CryptographicKeyFullModelBuilder.aKeySnapshot;
import static com.otilm.core.util.builders.CryptographicKeyItemBasicModelBuilder.aKeyItemSnapshot;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ModelIdentifierTest {

    @Test
    void toIdentifierString_returnsUuid_forUnnamedModel() {
        // given
        UUID uuid = UUID.randomUUID();
        IdentifiableModel model = () -> uuid;

        // when
        String identifier = model.toIdentifierString();

        // then
        assertEquals(uuid.toString(), identifier);
    }

    @Test
    void toIdentifierString_includesNameAndUuid() {
        // given
        String name = "Signing key";
        UUID uuid = UUID.randomUUID();
        NamedModel model = new NamedSnapshot(uuid, name);

        // when
        String identifier = model.toIdentifierString();

        // then
        assertEquals(name + " (" + uuid + ")", identifier);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t\r\n"})
    void toIdentifierString_returnsUuid_forMissingName(String name) {
        // given
        UUID uuid = UUID.randomUUID();
        NamedModel model = new NamedSnapshot(uuid, name);

        // when
        String identifier = model.toIdentifierString();

        // then
        assertEquals(uuid.toString(), identifier);
    }

    @Test
    void toIdentifierString_escapesLineBreaksInName() {
        // given
        String name = "Signing\r\nkey\u000Bnext\fline\u0085more\u2028text\u2029end";
        String escapedName = "Signing\\r\\nkey\\u000Bnext\\fline\\u0085more\\u2028text\\u2029end";
        UUID uuid = UUID.randomUUID();
        NamedModel model = new NamedSnapshot(uuid, name);

        // when
        String identifier = model.toIdentifierString();

        // then
        assertEquals(escapedName + " (" + uuid + ")", identifier);
    }

    @Test
    void toIdentifierString_excludesKeyMaterial_fromKeyAndItem() {
        // given
        String privateKeyMaterial = "private-key-material-must-not-appear";
        CryptographicKeyItemBasicModel item = aKeyItemSnapshot().withKeyData(privateKeyMaterial).build();
        var key = aKeySnapshot().withItems(List.of(item)).build();

        // when
        String keyIdentifier = key.toIdentifierString();
        String itemIdentifier = item.toIdentifierString();

        // then
        assertEquals(key.name() + " (" + key.uuid() + ")", keyIdentifier);
        assertEquals(item.name() + " (" + item.uuid() + ")", itemIdentifier);
    }

    private record NamedSnapshot(UUID uuid, String name) implements NamedModel {
    }
}

package com.otilm.core.model.crypto;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.enums.BitMaskEnum;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptographicKeyItemOperationRowTest {

    @Test
    void toModel_mapsUuidReference_andLegacyToken() {
        // given
        UUID reference = UUID.randomUUID();
        UUID keyUuid = UUID.randomUUID();
        String tokenInstanceUuid = UUID.randomUUID().toString();
        int signAndVerify = BitMaskEnum.convertSetToBitMask(EnumSet.of(KeyUsage.SIGN, KeyUsage.VERIFY));
        CryptographicKeyItemOperationRow row = new CryptographicKeyItemOperationRow(UUID.randomUUID(), true,
                KeyAlgorithm.RSA, KeyState.ACTIVE, KeyType.PRIVATE_KEY, signAndVerify, null, reference, null, keyUuid,
                UUID.randomUUID(), tokenInstanceUuid, null, null);

        // when
        CryptographicKeyItemOperationModel model = row.toModel();

        // then
        assertEquals(new RemoteKeyReference.UuidReference(reference), model.reference());
        assertEquals(List.of(KeyUsage.SIGN, KeyUsage.VERIFY), model.keyUsage());
        assertEquals(keyUuid, model.keyUuid());
        assertEquals(UUID.fromString(tokenInstanceUuid), model.tokenInstanceUuid());
        assertNull(model.pqcParameterSpecName());
        assertFalse(model.hasConnectorInterface());
    }

    @Test
    void toModel_mapsMetadataReference_andInterfaceColumns() {
        // given
        MetadataAttributeV3 handle = new MetadataAttributeV3();
        handle.setName("provider-handle");
        List<MetadataAttribute> keyMeta = List.of(handle);
        CryptographicKeyItemOperationRow row = new CryptographicKeyItemOperationRow(UUID.randomUUID(), true,
                KeyAlgorithm.MLDSA, KeyState.ACTIVE, KeyType.PRIVATE_KEY, 0, null, null, keyMeta, UUID.randomUUID(),
                UUID.randomUUID(), null, ConnectorInterface.CRYPTOGRAPHY, "v2");

        // when
        CryptographicKeyItemOperationModel model = row.toModel();

        // then
        assertEquals(new RemoteKeyReference.MetadataReference(keyMeta), model.reference());
        assertNull(model.tokenInstanceUuid());
        assertTrue(model.hasConnectorInterface());
        assertEquals(ConnectorInterface.CRYPTOGRAPHY, model.connectorInterfaceCode());
        assertEquals("v2", model.connectorInterfaceVersion());
    }
}

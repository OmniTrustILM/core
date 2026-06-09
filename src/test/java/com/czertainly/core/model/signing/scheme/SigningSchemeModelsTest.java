package com.czertainly.core.model.signing.scheme;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SigningSchemeModelsTest {

    @Test
    void delegatedSigning_reportsDelegatedScheme_andExposesFields() {
        UUID connectorUuid = UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        List<RequestAttribute> attrs = List.of();

        DelegatedSigning scheme = new DelegatedSigning(connectorUuid, attrs);

        assertEquals(SigningScheme.DELEGATED, scheme.getSchemeType());
        assertEquals(connectorUuid, scheme.connectorUuid());
        assertNotNull(scheme.connectorAttributes());
        assertInstanceOf(SigningSchemeModel.class, scheme);
    }

    @Test
    void staticKeyManagedSigning_reportsManagedScheme_andStaticKeyType() {
        StaticKeyManagedSigning scheme = new StaticKeyManagedSigning(
                UUID.fromString("cccccccc-cccc-cccc-cccc-cccccccccccc"),
                List.of());

        assertEquals(SigningScheme.MANAGED, scheme.getSchemeType());
        assertEquals(ManagedSigningType.STATIC_KEY, scheme.getManagedSigningType());
        assertInstanceOf(ManagedSigning.class, scheme);
        assertInstanceOf(SigningSchemeModel.class, scheme);
    }

    @Test
    void oneTimeKeyManagedSigning_reportsManagedScheme_andOneTimeKeyType() {
        OneTimeKeyManagedSigning scheme = new OneTimeKeyManagedSigning(
                UUID.fromString("dddddddd-dddd-dddd-dddd-dddddddddddd"),
                UUID.fromString("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"),
                UUID.fromString("ffffffff-ffff-ffff-ffff-ffffffffffff"),
                List.of());

        assertEquals(SigningScheme.MANAGED, scheme.getSchemeType());
        assertEquals(ManagedSigningType.ONE_TIME_KEY, scheme.getManagedSigningType());
        assertInstanceOf(ManagedSigning.class, scheme);
        assertInstanceOf(SigningSchemeModel.class, scheme);
    }
}

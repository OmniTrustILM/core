package com.otilm.core.service.handler;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorInterfaceInfo;
import com.otilm.api.model.core.connector.v2.ConnectInfoV2;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConnectorV2AdapterTest {

    // validateConnection(ConnectInfo) is a pure check over the supplied interface list, so it is exercised
    // without Spring/mocks; the autowired collaborators are deliberately left unset.
    private final ConnectorV2Adapter adapter = new ConnectorV2Adapter();

    @Test
    void missingMandatoryInterface_throws() {
        ConnectInfoV2 connectInfo = connectInfo(ConnectorInterface.INFO, ConnectorInterface.HEALTH);
        ValidationException ex = assertThrows(ValidationException.class,
                () -> adapter.validateConnection(connectInfo));
        assertTrue(ex.getMessage().contains("missing mandatory interfaces"), ex.getMessage());
    }

    @Test
    void onlyMandatoryCommons_throwsMissingFunctional() {
        ConnectInfoV2 connectInfo = connectInfo(
                ConnectorInterface.INFO, ConnectorInterface.HEALTH, ConnectorInterface.METRICS);
        ValidationException ex = assertThrows(ValidationException.class,
                () -> adapter.validateConnection(connectInfo));
        assertTrue(ex.getMessage().contains("functional"), ex.getMessage());
    }

    /** ATTRIBUTES is a common interface, so it must not count toward the functional-interface requirement. */
    @Test
    void commonsWithAttributes_throwsMissingFunctional() {
        ConnectInfoV2 connectInfo = connectInfo(
                ConnectorInterface.INFO, ConnectorInterface.HEALTH,
                ConnectorInterface.METRICS, ConnectorInterface.ATTRIBUTES);
        ValidationException ex = assertThrows(ValidationException.class,
                () -> adapter.validateConnection(connectInfo));
        assertTrue(ex.getMessage().contains("functional"), ex.getMessage());
    }

    @Test
    void mandatoryPlusFunctional_passes() throws ConnectorException {
        assertNotNull(adapter.validateConnection(connectInfo(
                ConnectorInterface.INFO, ConnectorInterface.HEALTH,
                ConnectorInterface.METRICS, ConnectorInterface.AUTHORITY)));
    }

    @Test
    void attributesPlusFunctional_passes() throws ConnectorException {
        assertNotNull(adapter.validateConnection(connectInfo(
                ConnectorInterface.INFO, ConnectorInterface.HEALTH, ConnectorInterface.METRICS,
                ConnectorInterface.ATTRIBUTES, ConnectorInterface.AUTHORITY)));
    }

    private static ConnectInfoV2 connectInfo(ConnectorInterface... codes) {
        ConnectInfoV2 connectInfo = new ConnectInfoV2();
        connectInfo.setInterfaces(Arrays.stream(codes).map(ConnectorV2AdapterTest::iface).toList());
        return connectInfo;
    }

    private static ConnectorInterfaceInfo iface(ConnectorInterface code) {
        return new ConnectorInterfaceInfo(code, "2.0", List.of());
    }
}

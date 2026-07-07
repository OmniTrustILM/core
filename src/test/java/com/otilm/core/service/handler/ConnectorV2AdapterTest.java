package com.otilm.core.service.handler;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorInterfaceInfo;
import com.otilm.api.model.core.connector.v2.ConnectInfoV2;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ConnectorV2AdapterTest {

    // validateConnection(ConnectInfo) is a pure check over the supplied interface list, so it is exercised
    // without Spring/mocks; the autowired collaborators are deliberately left unset.
    private final ConnectorV2Adapter adapter = new ConnectorV2Adapter();

    @Test
    void missingMandatoryInterface_throws() {
        ConnectInfoV2 connectInfo = connectInfo(ConnectorInterface.INFO, ConnectorInterface.HEALTH);
        assertThatThrownBy(() -> adapter.validateConnection(connectInfo))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("missing mandatory interfaces");
    }

    @Test
    void onlyMandatoryCommons_throwsMissingFunctional() {
        ConnectInfoV2 connectInfo = connectInfo(
                ConnectorInterface.INFO, ConnectorInterface.HEALTH, ConnectorInterface.METRICS);
        assertThatThrownBy(() -> adapter.validateConnection(connectInfo))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("functional");
    }

    /** ATTRIBUTES is a common interface, so it must not count toward the functional-interface requirement. */
    @Test
    void commonsWithAttributes_throwsMissingFunctional() {
        ConnectInfoV2 connectInfo = connectInfo(
                ConnectorInterface.INFO, ConnectorInterface.HEALTH,
                ConnectorInterface.METRICS, ConnectorInterface.ATTRIBUTES);
        assertThatThrownBy(() -> adapter.validateConnection(connectInfo))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("functional");
    }

    /** A malformed connector entry with a null interface code must be rejected as a validation error, not NPE. */
    @Test
    void malformedInterfaceWithNullCode_throws() {
        ConnectInfoV2 connectInfo = new ConnectInfoV2();
        connectInfo.setInterfaces(List.of(
                iface(ConnectorInterface.INFO), iface(ConnectorInterface.HEALTH),
                iface(ConnectorInterface.METRICS), iface(ConnectorInterface.AUTHORITY),
                new ConnectorInterfaceInfo(null, "2.0", List.of())));
        assertThatThrownBy(() -> adapter.validateConnection(connectInfo))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("no code");
    }

    @Test
    void mandatoryPlusFunctional_passes() throws ConnectorException {
        ConnectInfoV2 connectInfo = connectInfo(
                ConnectorInterface.INFO, ConnectorInterface.HEALTH,
                ConnectorInterface.METRICS, ConnectorInterface.AUTHORITY);
        assertThat(adapter.validateConnection(connectInfo)).isSameAs(connectInfo);
    }

    @Test
    void attributesPlusFunctional_passes() throws ConnectorException {
        ConnectInfoV2 connectInfo = connectInfo(
                ConnectorInterface.INFO, ConnectorInterface.HEALTH, ConnectorInterface.METRICS,
                ConnectorInterface.ATTRIBUTES, ConnectorInterface.AUTHORITY);
        assertThat(adapter.validateConnection(connectInfo)).isSameAs(connectInfo);
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

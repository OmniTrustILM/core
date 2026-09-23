package com.otilm.core.service.handler;

import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.connector.v2.FeatureFlag.FeatureFlagBehavior;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * Service-layer capability gate — defense-in-depth layer 2 between the protocol-level {@code instanceof <Capability>}
 * check (layer 1) and the connector-side {@code OPERATION_NOT_SUPPORTED} runtime error (layer 3).
 *
 * <p>
 * Resolves whether a connector advertises a {@link FeatureFlag} on the relevant interface:
 * <ul>
 * <li><b>ENFORCED</b> flags are opt-in — supported only when the connector explicitly advertises the flag on the
 * applicable interface; absent means unsupported.</li>
 * <li><b>INFORMATIONAL</b> flags pass through — Core handles the behavior regardless of whether it is advertised, so
 * {@code supports(...)} is always true.</li>
 * </ul>
 *
 * <p>
 * The ENFORCED/INFORMATIONAL gate is generic over any {@link FeatureFlag}; entry points resolve per bound interface
 * row, or per authority instance for the authority-typed convenience overload.
 */
@Service
public class ConnectorCapabilityService {

    /**
     * Per-interface-row check — keyed on the bound {@link ConnectorInterfaceEntity} rather than (connector, code), so
     * it is correct even when the connector exposes multiple versions of the same interface.
     */
    public boolean supports(ConnectorInterfaceEntity iface, FeatureFlag flag) {
        return supports(flag, iface == null ? null : iface.getFeatures());
    }

    /**
     * Per-authority check — reads the authority's own bound interface entity directly.
     */
    public boolean supports(AuthorityInstanceReference authority, FeatureFlag flag) {
        return supports(authority != null ? authority.getConnectorInterface() : null, flag);
    }

    /**
     * Per-snapshot check — for callers holding the immutable interface a model carries rather than the entity.
     */
    public boolean supports(ImmutableConnectorInterface iface, FeatureFlag flag) {
        return supports(flag, iface == null ? null : iface.features());
    }

    private static boolean supports(FeatureFlag flag, List<FeatureFlag> advertised) {
        if (flag.getBehavior() == FeatureFlagBehavior.INFORMATIONAL) {
            return true;
        }
        return advertised != null && advertised.contains(flag);
    }
}

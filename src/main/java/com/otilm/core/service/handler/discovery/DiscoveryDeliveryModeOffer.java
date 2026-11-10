package com.otilm.core.service.handler.discovery;

import com.otilm.api.model.connector.discovery.v2.DiscoveryDeliveryMode;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * The delivery modes Core offers a Discovery v2 connector on every request, in preference order. The connector picks
 * one at initiate and at resume.
 *
 * <p>
 * Configured as {@code discovery.delivery.modes}, a comma-separated list of wire codes. Dropping {@code checkpointed}
 * is the operator's switch for a broken release: a connector that supports only checkpointed delivery then refuses
 * every new run and every resume.
 */
@Component
public class DiscoveryDeliveryModeOffer {

    private static final String SETTING = "discovery.delivery.modes";

    private final List<DiscoveryDeliveryMode> offered;

    public DiscoveryDeliveryModeOffer(@Value("${discovery.delivery.modes:buffered}") String modes) {
        this.offered = parse(modes);
    }

    /** The offered modes, most preferred first. */
    public List<DiscoveryDeliveryMode> offered() {
        return offered;
    }

    public boolean offers(DiscoveryDeliveryMode mode) {
        return offered.contains(mode);
    }

    private static List<DiscoveryDeliveryMode> parse(String modes) {
        List<String> codes = modes == null
                ? List.of()
                : Arrays.stream(modes.split(",")).map(String::trim).filter(code -> !code.isEmpty()).toList();
        if (codes.isEmpty()) {
            throw new IllegalArgumentException(SETTING + " must name at least one delivery mode");
        }
        Set<DiscoveryDeliveryMode> parsed = new LinkedHashSet<>();
        for (String code : codes) {
            parsed.add(modeOf(code));
        }
        return List.copyOf(parsed);
    }

    private static DiscoveryDeliveryMode modeOf(String code) {
        for (DiscoveryDeliveryMode mode : DiscoveryDeliveryMode.values()) {
            if (mode.getCode().equals(code)) {
                return mode;
            }
        }
        List<String> knownCodes = Arrays
                .stream(DiscoveryDeliveryMode.values())
                .map(DiscoveryDeliveryMode::getCode)
                .toList();
        throw new IllegalArgumentException(
                "%s names an unknown delivery mode '%s'; known modes are %s".formatted(SETTING, code, knownCodes));
    }
}

package com.otilm.core.service.handler.discovery;

import com.otilm.api.model.connector.discovery.v2.DiscoveryDeliveryMode;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.FileSystemResource;
import org.springframework.util.PropertyPlaceholderHelper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DiscoveryDeliveryModeOfferTest {

    private static final Path SHIPPED_CONFIG = Path.of("src/main/resources/application.yml");

    @Test
    void offersBufferedOnly_whenTheShippedDefaultApplies() {
        // given
        String shippedDefault = shippedDefaultOf("discovery.delivery.modes");

        // when
        List<DiscoveryDeliveryMode> offered = new DiscoveryDeliveryModeOffer(shippedDefault).offered();

        // then
        assertThat(offered).containsExactly(DiscoveryDeliveryMode.BUFFERED);
    }

    @Test
    void offersModesInConfiguredOrder_whenCheckpointedComesFirst() {
        // given
        var checkpointedThenBuffered = "checkpointed, buffered";

        // when
        List<DiscoveryDeliveryMode> offered = new DiscoveryDeliveryModeOffer(checkpointedThenBuffered).offered();

        // then
        assertThat(offered).containsExactly(DiscoveryDeliveryMode.CHECKPOINTED, DiscoveryDeliveryMode.BUFFERED);
    }

    @Test
    void refusesToStart_whenAModeCodeIsUnknown() {
        // given
        var unknownCode = "buffered,streamed";

        // when
        ThrowingCallable parse = () -> new DiscoveryDeliveryModeOffer(unknownCode);

        // then
        assertThatThrownBy(parse)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("discovery.delivery.modes")
                .hasMessageContaining("streamed");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", ", ,"})
    void refusesToStart_whenNoModeIsConfigured(String nothingOffered) {
        // when
        ThrowingCallable parse = () -> new DiscoveryDeliveryModeOffer(nothingOffered);

        // then
        assertThatThrownBy(parse)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("discovery.delivery.modes");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** The value a property takes in the shipped configuration when no environment variable overrides it. */
    private static String shippedDefaultOf(String key) {
        YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
        yaml.setResources(new FileSystemResource(SHIPPED_CONFIG));
        Properties shipped = yaml.getObject();
        assertThat(shipped).isNotNull();
        String raw = shipped.getProperty(key);
        assertThat(raw).describedAs("%s must be declared in %s", key, SHIPPED_CONFIG).isNotNull();
        PropertyPlaceholderHelper defaultsOnly = new PropertyPlaceholderHelper("${", "}", ":", null, true);
        return defaultsOnly.replacePlaceholders(raw, placeholder -> null);
    }
}

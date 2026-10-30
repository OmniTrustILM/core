package com.otilm.core.util.mockbeans;

import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.messaging.jms.producers.NotificationProducer;
import com.otilm.core.messaging.jms.producers.ValidationProducer;
import com.otilm.core.messaging.model.NotificationMessage;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.boot.context.TypeExcludeFilter;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.context.event.EventListener;
import org.springframework.core.type.classreading.MetadataReader;
import org.springframework.core.type.classreading.MetadataReaderFactory;

import static org.mockito.Mockito.mock;

/**
 * Mocks the JMS producers (external-boundary I/O that tests never exercise for real).
 * <p>
 * Import it together with the component-scan exclusion it needs:
 *
 * <pre>
 * &#64;Import(ProducerMocks.class)
 * &#64;TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
 * </pre>
 *
 * Both are required, and {@code ProducerMocksExclusionArchTest} fails the build if one is missing.
 */
@TestConfiguration
public class ProducerMocks {

    @Bean
    @Primary
    NotificationProducer mockNotificationProducer() {
        return mock(NotificationProducer.class);
    }

    @Bean
    @Primary
    ActionProducer mockActionProducer() {
        return mock(ActionProducer.class);
    }

    @Bean
    @Primary
    EventProducer mockEventProducer() {
        return mock(EventProducer.class);
    }

    @Bean
    @Primary
    ValidationProducer mockValidationProducer() {
        return mock(ValidationProducer.class);
    }

    @Bean
    RecordedNotificationMessages recordedNotificationMessages() {
        return new RecordedNotificationMessages();
    }

    /**
     * Records every {@link NotificationMessage} published as an application event, synchronously at publish time. The
     * mocked {@link NotificationProducer} never forwards messages to the broker, so tests assert on this recorder — and
     * can replay a captured message into the listener — instead of consuming JMS.
     */
    public static class RecordedNotificationMessages {

        private final List<NotificationMessage> messages = new CopyOnWriteArrayList<>();

        @EventListener
        public void onNotificationMessage(NotificationMessage message) {
            messages.add(message);
        }

        public List<NotificationMessage> messages() {
            return List.copyOf(messages);
        }

        public void clear() {
            messages.clear();
        }
    }

    /**
     * Keeps the classes mocked above out of the component scan. Named in {@code @TypeExcludeFilters} on each importing
     * test class, which registers it before the context refreshes — a {@code @Bean} here would be registered only after
     * the scan has already run.
     * <p>
     * {@code equals}/{@code hashCode} are stateless on purpose: they keep every test declaring this filter on one
     * context-cache key.
     */
    public static final class MockedProducersTypeExcludeFilter extends TypeExcludeFilter {

        private static final Set<String> EXCLUDED_CLASS_NAMES = Stream
                .of(NotificationProducer.class, ActionProducer.class, EventProducer.class, ValidationProducer.class)
                .map(Class::getName)
                .collect(Collectors.toUnmodifiableSet());

        @Override
        public boolean match(MetadataReader metadataReader, MetadataReaderFactory metadataReaderFactory) {
            return EXCLUDED_CLASS_NAMES.contains(metadataReader.getClassMetadata().getClassName());
        }

        @Override
        public boolean equals(Object obj) {
            return obj != null && getClass() == obj.getClass();
        }

        @Override
        public int hashCode() {
            return getClass().hashCode();
        }
    }
}

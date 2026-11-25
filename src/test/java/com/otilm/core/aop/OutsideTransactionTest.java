package com.otilm.core.aop;

import java.io.IOException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.interceptor.TransactionAttribute;

import static org.assertj.core.api.Assertions.assertThat;

class OutsideTransactionTest {

    @ParameterizedTest
    @ValueSource(classes = {SpringTransactionalService.class, JakartaTransactionalService.class})
    void runsTheMethodWithNoTransaction_whenItsClassIsTransactional(Class<?> service) throws NoSuchMethodException {
        // when
        TransactionAttribute attribute = new AnnotationTransactionAttributeSource()
                .getTransactionAttribute(service.getMethod("call"), service);

        // then
        assertThat(attribute).isNotNull();
        assertThat(attribute.getPropagationBehavior()).isEqualTo(TransactionDefinition.PROPAGATION_NOT_SUPPORTED);
    }

    @Transactional
    static class SpringTransactionalService {

        @OutsideTransaction
        public void call() throws IOException {
            // only its annotations are read
        }
    }

    @jakarta.transaction.Transactional
    static class JakartaTransactionalService {

        @OutsideTransaction
        public void call() throws IOException {
            // only its annotations are read
        }
    }
}

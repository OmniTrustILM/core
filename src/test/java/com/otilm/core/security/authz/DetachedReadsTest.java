package com.otilm.core.security.authz;

import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DetachedReadsTest {

    @Mock
    EntityManagerFactory entityManagerFactory;

    @Mock
    EntityManager reader;

    @BeforeEach
    void stubOwnEntityManager() {
        when(entityManagerFactory.createEntityManager()).thenReturn(reader);
    }

    @Test
    void closesItsEntityManager_whenTheReadSucceeds() {
        // given
        String readValue = "read";

        // when
        String result = DetachedReads.read(entityManagerFactory, entityManager -> readValue);

        // then
        assertThat(result).isEqualTo(readValue);
        verify(reader).close();
    }

    @Test
    void closesItsEntityManager_whenTheReadFails() {
        // given
        IllegalStateException readFailure = new IllegalStateException("connection lost");

        // when
        ThrowingCallable failingRead = () -> DetachedReads.read(entityManagerFactory, entityManager -> {
            throw readFailure;
        });

        // then
        assertThatThrownBy(failingRead).isSameAs(readFailure);
        verify(reader).close();
    }
}

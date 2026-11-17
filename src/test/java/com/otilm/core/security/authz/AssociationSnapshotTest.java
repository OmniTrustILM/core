package com.otilm.core.security.authz;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.util.PrincipalFixtures;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.PersistenceException;
import jakarta.persistence.Tuple;
import jakarta.persistence.TypedQuery;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AssociationSnapshotTest {

    @Mock
    EntityManagerFactory entityManagerFactory;

    @Mock
    EntityManager entityManager;

    AssociationSnapshot snapshot;

    @BeforeEach
    void createSnapshotOverMockedReader() {
        PlatformUserDetails principal = PrincipalFixtures
                .authentication(PrincipalFixtures.operatorProfile(UUID.randomUUID().toString(), "operator"))
                .getPrincipal();
        snapshot = new AssociationSnapshot(entityManagerFactory, new ObjectMapper(), principal);
        when(entityManagerFactory.createEntityManager()).thenReturn(entityManager);
    }

    @Test
    void retriesTheGroupRead_whenAnEarlierReadFailed() {
        // given
        UUID failedFirst = UUID.randomUUID();
        UUID askedLater = UUID.randomUUID();
        UUID group = UUID.randomUUID();
        snapshot.prefetch(Resource.CERTIFICATE, List.of(failedFirst, askedLater));
        TypedQuery<Tuple> query = stubQuery(Tuple.class);
        Tuple failedFirstRow = createRow(failedFirst, group);
        Tuple askedLaterRow = createRow(askedLater, group);
        when(query.getResultList())
                .thenThrow(new PersistenceException("connection lost"))
                .thenReturn(List.of(failedFirstRow, askedLaterRow));

        // when
        ThrowingCallable failingGroupRead = () -> snapshot.groupsOf(Resource.CERTIFICATE, failedFirst);

        // then
        assertThatThrownBy(failingGroupRead).isInstanceOf(PersistenceException.class);
        List<String> groupsAskedLater = snapshot.groupsOf(Resource.CERTIFICATE, askedLater);
        List<String> groupsFailedFirst = snapshot.groupsOf(Resource.CERTIFICATE, failedFirst);
        assertThat(groupsAskedLater).containsExactly(group.toString());
        assertThat(groupsFailedFirst).containsExactly(group.toString());
        verify(query, times(2)).setParameter("objectUuids", Set.of(failedFirst, askedLater));
        verify(query, times(2)).getResultList();
        verify(entityManager, times(2)).close();
    }

    @Test
    void retriesTheOwnerRead_whenAnEarlierReadFailed() {
        // given
        UUID failedFirst = UUID.randomUUID();
        UUID askedLater = UUID.randomUUID();
        snapshot.prefetch(Resource.CERTIFICATE, List.of(failedFirst, askedLater));
        TypedQuery<UUID> query = stubQuery(UUID.class);
        when(query.getResultList())
                .thenThrow(new PersistenceException("connection lost"))
                .thenReturn(List.of(failedFirst, askedLater));

        // when
        ThrowingCallable failingOwnerRead = () -> snapshot.ownsAll(Resource.CERTIFICATE, List.of(failedFirst));

        // then
        assertThatThrownBy(failingOwnerRead).isInstanceOf(PersistenceException.class);
        boolean ownsAskedLater = snapshot.ownsAll(Resource.CERTIFICATE, List.of(askedLater));
        boolean ownsFailedFirst = snapshot.ownsAll(Resource.CERTIFICATE, List.of(failedFirst));
        assertThat(ownsAskedLater).isTrue();
        assertThat(ownsFailedFirst).isTrue();
        verify(query, times(2)).setParameter("objectUuids", Set.of(failedFirst, askedLater));
        verify(query, times(2)).getResultList();
        verify(entityManager, times(2)).close();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private <T> TypedQuery<T> stubQuery(Class<T> resultType) {
        TypedQuery<T> query = mock(TypedQuery.class, Mockito.RETURNS_SELF);
        when(entityManager.createQuery(any(String.class), eq(resultType))).thenReturn(query);
        return query;
    }

    private static Tuple createRow(UUID objectUuid, UUID groupUuid) {
        Tuple row = mock(Tuple.class);
        when(row.get(0, UUID.class)).thenReturn(objectUuid);
        when(row.get(1, UUID.class)).thenReturn(groupUuid);
        return row;
    }
}

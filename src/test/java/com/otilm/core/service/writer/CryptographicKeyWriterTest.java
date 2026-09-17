package com.otilm.core.service.writer;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.cryptography.key.KeyCompromiseReason;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.service.CryptographicKeyEventHistoryService;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.builders.CryptographicKeyItemBuilder.aKeyItem;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CryptographicKeyWriterTest {

    @Mock
    private CryptographicKeyItemRepository items;
    @Mock
    private CryptographicKeyEventHistoryService history;
    @InjectMocks
    private CryptographicKeyWriter writer;

    @ParameterizedTest
    @EnumSource(value = KeyState.class, names = {"PRE_ACTIVE", "ACTIVE", "DEACTIVATED"})
    void compromise_acceptsEveryPermittedState(KeyState initialState) throws NotFoundException {
        // given
        var item = keyItem(initialState);
        KeyCompromiseReason requestedReason = KeyCompromiseReason.UNAUTHORIZED_DISCLOSURE;

        // when
        Optional<String> rejection = writer.setKeyItemCompromised(item.getUuid(), requestedReason);

        // then
        assertThat(rejection).isEmpty();
        assertThat(item.getState()).isEqualTo(KeyState.COMPROMISED);
        assertThat(item.getReason()).isEqualTo(requestedReason);
        verify(items).save(item);
        verify(history)
                .addEventHistory(eq(KeyEvent.COMPROMISED), eq(KeyEventStatus.SUCCESS), any(), isNull(),
                        eq(item.getUuid()));
    }

    @ParameterizedTest
    @EnumSource(value = KeyState.class, names = {"PRE_ACTIVE", "ACTIVE", "DEACTIVATED"}, mode = EnumSource.Mode.EXCLUDE)
    void compromise_preservesEveryRejectedState(KeyState initialState) throws NotFoundException {
        // given
        var item = keyItem(initialState);
        KeyCompromiseReason originalReason = KeyCompromiseReason.UNAUTHORIZED_DISCLOSURE;
        KeyCompromiseReason requestedReason = KeyCompromiseReason.UNAUTHORIZED_MODIFICATION;
        item.setReason(originalReason);

        // when
        Optional<String> rejection = writer.setKeyItemCompromised(item.getUuid(), requestedReason);

        // then
        assertThat(rejection)
                .hasValueSatisfying(
                        message -> assertThat(message).contains(item.getUuid().toString(), initialState.getLabel()));
        assertThat(item.getState()).isEqualTo(initialState);
        assertThat(item.getReason()).isEqualTo(originalReason);
        verify(items, never()).save(any());
        verify(history)
                .addEventHistory(eq(KeyEvent.COMPROMISED), eq(KeyEventStatus.FAILED), eq(rejection.orElseThrow()),
                        isNull(), eq(item.getUuid()));
    }

    @Test
    void compromise_rejectsMissingItem() {
        // given
        UUID missingItem = UUID.randomUUID();

        // when
        Executable compromise = () -> writer.setKeyItemCompromised(missingItem, null);

        // then
        assertThat(assertThrows(NotFoundException.class, compromise)).hasMessageContaining(missingItem.toString());
        verify(items, never()).save(any());
        verifyNoInteractions(history);
    }

    @Test
    void updateUsage_canClearUsages() throws NotFoundException {
        // given
        var item = keyItem(KeyState.ACTIVE);
        item.setUsage(List.of(KeyUsage.SIGN));
        List<KeyUsage> clearedUsages = List.of();

        // when
        Optional<String> rejection = writer.updateUsage(item.getUuid(), clearedUsages);

        // then
        assertThat(rejection).isEmpty();
        assertThat(item.getUsage()).isEmpty();
        verify(items).save(item);
        verify(history)
                .addEventHistory(eq(KeyEvent.UPDATE_USAGE), eq(KeyEventStatus.SUCCESS),
                        contains(KeyUsage.SIGN.getCode()), isNull(), eq(item.getUuid()));
    }

    @Test
    void updateUsage_rejectsMissingItem() {
        // given
        UUID missingItem = UUID.randomUUID();

        // when
        Executable update = () -> writer.updateUsage(missingItem, List.of());

        // then
        assertThat(assertThrows(NotFoundException.class, update)).hasMessageContaining(missingItem.toString());
        verify(items, never()).save(any());
        verifyNoInteractions(history);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void setKeyItemEnabled_doesNotRecordSuccessWhenNothingChanged(boolean requestedEnabled) {
        // given
        UUID unchangedItem = UUID.randomUUID();
        when(items.updateEnabledIfChanged(unchangedItem, requestedEnabled)).thenReturn(0);

        // when
        boolean changed = writer.setKeyItemEnabled(unchangedItem, requestedEnabled);

        // then
        assertThat(changed).isFalse();
        verifyNoInteractions(history);
    }

    private CryptographicKeyItem keyItem(KeyState state) {
        CryptographicKeyItem item = aKeyItem().withType(KeyType.PRIVATE_KEY).withState(state).build();
        item.setUuid(UUID.randomUUID());
        item.setKeyAlgorithm(KeyAlgorithm.RSA);
        when(items.findForUpdateByUuid(item.getUuid())).thenReturn(Optional.of(item));
        return item;
    }
}

package com.otilm.core.settings;

import com.otilm.api.model.core.settings.SettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.stereotype.Component;

@Component
public class SettingsCache {

    // In-memory cache for all sections except AUTHENTICATION
    private static final Map<SettingsSection, SettingsDto> cache = new ConcurrentHashMap<>();

    // The single authoritative holder for AUTHENTICATION: settings paired with a generation
    // that changes only when the settings change.
    private static final AtomicReference<AuthenticationSettingsSnapshot> authenticationSnapshot = new AtomicReference<>(
            new AuthenticationSettingsSnapshot(null, 0L));

    // Get a setting value by key
    public static <T extends SettingsDto> T getSettings(SettingsSection settingsSection) {
        if (settingsSection == SettingsSection.AUTHENTICATION) {
            return (T) authenticationSnapshot.get().settings();
        }
        return (T) cache.get(settingsSection);
    }

    public static AuthenticationSettingsSnapshot getAuthenticationSnapshot() {
        return authenticationSnapshot.get();
    }

    // Cache settings
    public void cacheSettings(SettingsSection settingsSection, SettingsDto settingsDto) {
        if (settingsSection == SettingsSection.AUTHENTICATION) {
            authenticationSnapshot
                    .updateAndGet(current -> Objects.equals(current.settings(), settingsDto)
                            ? current
                            : new AuthenticationSettingsSnapshot((AuthenticationSettingsDto) settingsDto,
                                    current.generation() + 1));
            return;
        }
        cache.put(settingsSection, settingsDto);
    }
}

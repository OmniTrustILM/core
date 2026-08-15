package com.otilm.core.dao.repository;

import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.core.dao.entity.Setting;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface SettingRepository extends SecurityFilterRepository<Setting, UUID> {

    Optional<Setting> findByUuid(UUID uuid);

    List<Setting> findBySection(SettingsSection section);

    List<Setting> findBySectionAndCategory(SettingsSection section, String category);

    Setting findBySectionAndCategoryAndName(SettingsSection section, String category, String name);

    void deleteBySectionAndCategory(SettingsSection section, String category);

    Long deleteBySectionAndCategoryAndName(SettingsSection section, String category, String name);

    // Transaction-scoped advisory lock serializing OAuth2 provider settings writes so that concurrent
    // updates cannot both pass the in-process issuer-uniqueness check before either commits.
    @Query(value = "SELECT pg_advisory_xact_lock(hashtext('oauth2-provider-settings'))", nativeQuery = true)
    Object lockOAuth2ProviderWrites();

    // Transaction-scoped advisory lock serializing branding writes. Branding is one row per field, each written by
    // reading the existing row and inserting when there is none, so without this two first updates could both observe
    // no row and insert the same field.
    @Query(value = "SELECT pg_advisory_xact_lock(hashtext('platform-branding-settings'))", nativeQuery = true)
    Object lockBrandingWrites();
}

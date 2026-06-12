package com.otilm.core.dao.repository;

import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.core.dao.entity.Setting;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SettingRepository extends SecurityFilterRepository<Setting, UUID> {

    Optional<Setting> findByUuid(UUID uuid);

    List<Setting> findBySection(SettingsSection section);

    List<Setting> findBySectionAndCategory(SettingsSection section, String category);

    Setting findBySectionAndCategoryAndName(SettingsSection section, String category, String name);

    void deleteBySectionAndCategory(SettingsSection section, String category);

    Long deleteBySectionAndCategoryAndName(SettingsSection section, String category, String name);
}

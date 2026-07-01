package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.RaProfileValueSourceBinding;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface RaProfileValueSourceBindingRepository extends SecurityFilterRepository<RaProfileValueSourceBinding, Long> {

    List<RaProfileValueSourceBinding> findByRaProfileUuid(UUID raProfileUuid);

    void deleteByRaProfileUuid(UUID raProfileUuid);
}

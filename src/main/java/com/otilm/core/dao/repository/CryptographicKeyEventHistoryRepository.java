package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CryptographicKeyEventHistory;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface CryptographicKeyEventHistoryRepository extends SecurityFilterRepository<CryptographicKeyEventHistory, UUID> {

    List<CryptographicKeyEventHistory> findByKeyOrderByCreatedDesc(CryptographicKeyItem key);

}

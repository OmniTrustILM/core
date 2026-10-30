package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CryptographicKeyEventHistory;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public interface CryptographicKeyEventHistoryRepository
        extends
            SecurityFilterRepository<CryptographicKeyEventHistory, UUID> {

    List<CryptographicKeyEventHistory> findByKeyOrderByCreatedDesc(CryptographicKeyItem key);

}

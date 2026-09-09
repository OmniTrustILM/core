package com.otilm.core.dao.repository.signing;

import com.otilm.core.dao.entity.signing.SigningRecordVolume;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import java.util.UUID;
import org.springframework.stereotype.Repository;

/**
 * Read access to the rolled-up signing history. The buckets themselves are written by the roll-up-then-delete
 * statements on {@link SigningRecordRepository}, never through this repository.
 */
@Repository
public interface SigningRecordVolumeRepository extends SecurityFilterRepository<SigningRecordVolume, UUID> {
}

package com.otilm.core.service.writer.cbom;

import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.model.cbom.CbomHeaderCounts;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Replaces a CBOM row's header counts with the ones the asset ingest recounted from the document.
 *
 * <p>
 * The feed's counts are advisory: an object uploaded before the repository's version-2 count carries a shallow one, and
 * nothing on the wire says which kind a count is. The recount is the value that stands once an ingest has read the
 * document.
 */
@Service
public class CbomHeaderCountsWriter {

    private final CbomRepository cbomRepository;

    public CbomHeaderCountsWriter(CbomRepository cbomRepository) {
        this.cbomRepository = cbomRepository;
    }

    /** @return 1 if the counts were written, 0 if the row no longer exists */
    @Transactional
    public int replace(UUID cbomUuid, CbomHeaderCounts counts) {
        return cbomRepository
                .updateHeaderCounts(cbomUuid, counts.algorithms(), counts.certificates(), counts.protocols(),
                        counts.cryptoMaterial(), counts.totalAssets());
    }
}

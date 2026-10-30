package com.otilm.core.service.writer;

import com.otilm.core.dao.entity.ListView;
import com.otilm.core.dao.repository.ListViewRepository;
import jakarta.persistence.EntityManager;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ListViewWriter {

    private final ListViewRepository listViewRepository;
    private final EntityManager entityManager;

    @Autowired
    public ListViewWriter(ListViewRepository listViewRepository, EntityManager entityManager) {
        this.listViewRepository = listViewRepository;
        this.entityManager = entityManager;
    }

    /**
     * Writes the view, clearing the flag on the user's previous default for the same resource first where it claims to
     * be the default. Clearing has to precede the write, because the partial unique index refuses the moment a second
     * default row exists. The uuid is assigned here rather than at persist time so the statement that clears the others
     * can name the row being kept.
     */
    @Transactional
    public ListView save(ListView view) {
        if (view.getUuid() == null) {
            view.setUuid(UUID.randomUUID());
        }
        if (view.isDefaultView()) {
            // An incoming entity that is already managed and already marked default would be auto-flushed by the
            // demotion query - Hibernate auto-flushes the tables a bulk update touches - and the partial unique index
            // would see two default rows. Detaching leaves nothing to flush, so the demotion runs first and the
            // promotion is written by the merge below.
            entityManager.detach(view);
            listViewRepository.clearDefaultExcept(view.getUserUuid(), view.getResource(), view.getUuid());
        }
        return listViewRepository.saveAndFlush(view);
    }

    @Transactional
    public void delete(UUID uuid) {
        listViewRepository.deleteById(uuid);
    }

    @Transactional
    public int deleteAllForUser(UUID userUuid) {
        return listViewRepository.deleteByUserUuid(userUuid);
    }
}

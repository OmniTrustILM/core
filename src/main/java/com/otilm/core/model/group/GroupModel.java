package com.otilm.core.model.group;

import com.otilm.core.dao.entity.Group;
import java.util.UUID;

/** Group snapshot without persistence associations. */
public record GroupModel(UUID uuid, String name, String description, String email) {

    public static GroupModel from(Group group) {
        return new GroupModel(group.getUuid(), group.getName(), group.getDescription(), group.getEmail());
    }
}

package com.otilm.core.dao.entity.oid;

import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;

@Entity
@DiscriminatorValue("GENERIC")
public class GenericCustomOidEntry extends CustomOidEntry {
}

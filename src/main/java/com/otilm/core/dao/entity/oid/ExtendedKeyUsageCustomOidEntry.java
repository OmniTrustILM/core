package com.otilm.core.dao.entity.oid;

import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;

@Entity
@DiscriminatorValue("EXTENDED_KEY_USAGE")
public class ExtendedKeyUsageCustomOidEntry extends CustomOidEntry {
}

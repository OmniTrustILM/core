package com.otilm.core.dao.entity.ai;

import com.otilm.core.dao.entity.UniquelyIdentified;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import org.hibernate.annotations.Immutable;

@Entity
@Immutable
@Table(name = "ai_runtime_run")
public class AiRuntimeRun extends UniquelyIdentified {
}

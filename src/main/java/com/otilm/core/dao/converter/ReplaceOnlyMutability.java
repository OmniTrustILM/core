package com.otilm.core.dao.converter;

import java.io.Serializable;
import org.hibernate.SharedSessionContract;
import org.hibernate.type.descriptor.java.Immutability;
import org.hibernate.type.descriptor.java.MutabilityPlan;

/**
 * Mutability of a value the code only replaces through the attribute's setter and never changes in place. The value
 * loaded or written last is its own snapshot, so the dirty check sees the attribute unchanged until it is replaced. A
 * change made in place is not detected: it is written only when a full-row update for another column carries it, never
 * on a {@code @DynamicUpdate} entity.
 *
 * <p>
 * Use it where a copy of the value never equals the original, such as JSON-mapped attributes whose nested types have no
 * value equality: with a copy as the snapshot, the column would be written on every flush. Unlike {@link Immutability},
 * the value still counts as mutable, so Hibernate compares it at flush. An enhanced entity tracks only the size of a
 * collection-typed field, and Hibernate does not compare an immutable attribute, so with {@link Immutability} a
 * replacement with as many elements as the loaded value would never be written.
 * </p>
 *
 * <p>
 * Hibernate registers a JSON-mapped Java type once per declared type, with the plan of the first attribute it resolves,
 * and every attribute of that type shares it. Every JSON attribute of the same declared type therefore declares this
 * plan, so none depends on which entity Hibernate reads first.
 * </p>
 */
public class ReplaceOnlyMutability implements MutabilityPlan<Object> {

    @Override
    public boolean isMutable() {
        return true;
    }

    @Override
    public Object deepCopy(Object value) {
        return value;
    }

    @Override
    public Serializable disassemble(Object value, SharedSessionContract session) {
        return (Serializable) value;
    }

    @Override
    public Object assemble(Serializable cached, SharedSessionContract session) {
        return cached;
    }
}

package com.otilm.core.dao.converter;

import java.io.Serializable;
import org.hibernate.SharedSessionContract;
import org.hibernate.type.descriptor.java.Immutability;
import org.hibernate.type.descriptor.java.MutabilityPlan;

/**
 * Mutability of a value the code only replaces through the attribute's setter and never changes in place. The value
 * loaded or written last is its own snapshot, so the dirty check sees the attribute unchanged until it is replaced.
 *
 * <p>
 * Use it where a copy of the value never equals the original, such as JSON-mapped attributes whose nested types have no
 * value equality: with a copy as the snapshot, the column would be written on every flush. Unlike {@link Immutability},
 * the value still counts as mutable, so Hibernate compares it at flush. An enhanced entity records no setter call for a
 * collection-typed field, and Hibernate does not compare an immutable attribute, so with {@link Immutability} a
 * replaced collection would never be written.
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

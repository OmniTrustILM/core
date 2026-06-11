package com.otilm.core.dao.entity;

import com.otilm.api.model.core.settings.SettingsSection;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.util.Objects;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "setting")
public class Setting extends UniquelyIdentifiedAndAudited {

    @Column(name = "section", nullable = false)
    @Enumerated(EnumType.STRING)
    private SettingsSection section;

    @Column(name = "category")
    private String category;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "value", length = Integer.MAX_VALUE)
    private String value;

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        Class<?> oEffectiveClass = o instanceof HibernateProxy ? ((HibernateProxy) o).getHibernateLazyInitializer().getPersistentClass() : o.getClass();
        Class<?> thisEffectiveClass = this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass() : this.getClass();
        if (thisEffectiveClass != oEffectiveClass) return false;
        Setting setting = (Setting) o;
        return getUuid() != null && Objects.equals(getUuid(), setting.getUuid());
    }

    @Override
    public final int hashCode() {
        return this instanceof HibernateProxy ? ((HibernateProxy) this).getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
    }
}

package com.otilm.core.dao.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.proxy.HibernateProxy;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Entity
@Table(name = "connector_2_function_group")
public class Connector2FunctionGroup implements Serializable {
	
	@Id
	@Column(name = "id")
	@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "connector_2_function_group_seq")
	@SequenceGenerator(name = "connector_2_function_group_seq", sequenceName = "connector_2_function_group_id_seq", allocationSize = 1)
	private Long id;
	
	@ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "connector_uuid", nullable = false, insertable = false, updatable = false)
    @JsonIgnore
	@ToString.Exclude
	private Connector connector;

	@Column(name = "connector_uuid", nullable = false)
	private UUID connectorUuid;

	@ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "function_group_uuid", nullable = false, insertable = false, updatable = false)
	@ToString.Exclude
	@JsonBackReference
	private FunctionGroup functionGroup;

	@Column(name = "function_group_uuid", nullable = false)
	private UUID functionGroupUuid;
	
	@Column(name = "kinds")
	private String kinds;

	public void setConnector(Connector connector) {
		this.connector = connector;
		this.connectorUuid = connector.getUuid();
	}

	public void setFunctionGroup(FunctionGroup functionGroup) {
		this.functionGroup = functionGroup;
		this.functionGroupUuid = functionGroup.getUuid();
	}

	@Override
	public final boolean equals(Object o) {
		if (this == o) return true;
		if (o == null) return false;
		Class<?> oEffectiveClass = o instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : o.getClass();
		Class<?> thisEffectiveClass = this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass() : this.getClass();
		if (thisEffectiveClass != oEffectiveClass) return false;
		Connector2FunctionGroup that = (Connector2FunctionGroup) o;
		return getId() != null && Objects.equals(getId(), that.getId());
	}

	@Override
	public final int hashCode() {
		return this instanceof HibernateProxy proxy ? proxy.getHibernateLazyInitializer().getPersistentClass().hashCode() : getClass().hashCode();
	}
}

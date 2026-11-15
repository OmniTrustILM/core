package com.otilm.core.dao.entity;

import com.otilm.api.model.connector.signatures.contentsigning.declaration.ContentSigningDeclarationDto;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** Content-signing declaration Core read from a formatting connector when it last connected or reconnected it. */
@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "connector_content_signing_declaration")
public class ConnectorContentSigningDeclaration {

    @Id
    @Column(name = "connector_uuid", nullable = false)
    private UUID connectorUuid;

    @Column(name = "declaration", nullable = false, columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private ContentSigningDeclarationDto declaration;
}

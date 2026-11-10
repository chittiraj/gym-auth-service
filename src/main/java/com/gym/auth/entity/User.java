package com.gym.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * Maps the existing {@code users} table. The schema is owned by the database, so this mapping only
 * describes it (ddl-auto=validate); it never creates or alters it.
 */
@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "user_id")
	private Long userId;

	@Column(name = "full_name", nullable = false, length = 150)
	private String fullName;

	@Column(name = "email", nullable = false, length = 150, unique = true)
	private String email;

	@Column(name = "password_hash", nullable = false, length = 255)
	private String passwordHash;

	@Column(name = "phone", length = 20)
	private String phone;

	@JdbcTypeCode(SqlTypes.LONGVARCHAR)
	@Column(name = "address", columnDefinition = "TEXT")
	private String address;

	@Column(name = "emergency_contact_name", length = 150)
	private String emergencyContactName;

	@Column(name = "emergency_contact_phone", length = 20)
	private String emergencyContactPhone;

	@Enumerated(EnumType.STRING)
	@JdbcTypeCode(SqlTypes.ENUM)
	@Column(name = "role", nullable = false)
	private Role role;

	@Column(name = "is_active", nullable = false)
	private boolean active;

	@Column(name = "created_at", nullable = false, updatable = false)
	private LocalDateTime createdAt;

	@Column(name = "updated_at", nullable = false)
	private LocalDateTime updatedAt;

}

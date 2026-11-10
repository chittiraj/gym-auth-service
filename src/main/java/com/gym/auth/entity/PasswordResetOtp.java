package com.gym.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Maps the existing {@code password_reset_otps} table. Only a BCrypt hash of the OTP is stored.
 * Lifecycle: created -> verified (verified_at) -> consumed or invalidated (used_at).
 */
@Entity
@Table(name = "password_reset_otps")
@Getter
@Setter
@NoArgsConstructor
public class PasswordResetOtp {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "otp_id")
	private Long otpId;

	@Column(name = "user_id", nullable = false, updatable = false)
	private Long userId;

	@Column(name = "otp_hash", nullable = false, length = 255)
	private String otpHash;

	@Column(name = "expires_at", nullable = false)
	private LocalDateTime expiresAt;

	@Column(name = "verified_at")
	private LocalDateTime verifiedAt;

	@Column(name = "used_at")
	private LocalDateTime usedAt;

	@Column(name = "attempts", nullable = false)
	private int attempts;

	@Column(name = "created_at", nullable = false, updatable = false)
	private LocalDateTime createdAt;

}

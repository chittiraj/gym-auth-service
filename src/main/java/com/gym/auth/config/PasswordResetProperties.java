package com.gym.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Forgot-password / OTP policy.
 *
 * @param otpExpirationMs        lifetime of a generated OTP
 * @param maxAttempts            incorrect OTP submissions allowed before the OTP is exhausted
 * @param resendCooldownSeconds  minimum gap between two OTP issues for the same account
 * @param maxRequestsPerHour     maximum OTP issues for one account within a rolling hour
 */
@ConfigurationProperties(prefix = "app.password-reset")
public record PasswordResetProperties(long otpExpirationMs, int maxAttempts, long resendCooldownSeconds,
		int maxRequestsPerHour) {
}

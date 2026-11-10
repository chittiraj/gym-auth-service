package com.gym.auth.dto;

import java.time.Instant;

/**
 * Returned once, on the first successful OTP verification. The resetToken is the only way to call
 * reset-password; it is bound to the verified OTP row and expires with that OTP.
 */
public record VerifyOtpResponse(
		String message,
		String resetToken,
		Instant expiresAt
) {
}

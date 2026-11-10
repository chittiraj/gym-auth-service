package com.gym.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record VerifyOtpRequest(
		@NotBlank @Email @Size(max = 150) String email,
		@NotBlank @Pattern(regexp = ValidationPatterns.OTP_REGEX, message = ValidationPatterns.OTP_MESSAGE) String otp
) {
}

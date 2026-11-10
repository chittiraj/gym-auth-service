package com.gym.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
		@NotBlank @Size(max = 150) String fullName,
		@NotBlank @Email @Size(max = 150) String email,
		@NotBlank @Pattern(regexp = ValidationPatterns.PASSWORD_REGEX, message = ValidationPatterns.PASSWORD_MESSAGE) String password,
		@Pattern(regexp = ValidationPatterns.PHONE_REGEX, message = ValidationPatterns.PHONE_MESSAGE) @Size(max = 20) String phone,
		@Size(max = 500) String address,
		@Size(max = 150) String emergencyContactName,
		@Pattern(regexp = ValidationPatterns.PHONE_REGEX, message = ValidationPatterns.PHONE_MESSAGE) @Size(max = 20) String emergencyContactPhone
) {
}

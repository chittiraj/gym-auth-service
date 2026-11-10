package com.gym.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Existing passwords are not policy-checked at login, so only presence and length are validated. */
public record LoginRequest(
		@NotBlank @Email @Size(max = 150) String email,
		@NotBlank @Size(max = 72) String password
) {
}

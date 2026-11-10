package com.gym.auth.dto;

import com.gym.auth.entity.Role;
import java.time.LocalDateTime;

/** Safe user representation. Never includes password_hash or emergency contact data. */
public record UserResponse(
		Long userId,
		String fullName,
		String email,
		String phone,
		String address,
		Role role,
		boolean isActive,
		LocalDateTime createdAt
) {
}

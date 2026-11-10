package com.gym.auth.service;

import com.gym.auth.dto.ChangePasswordRequest;
import com.gym.auth.dto.LoginRequest;
import com.gym.auth.dto.LoginResponse;
import com.gym.auth.dto.RegisterRequest;
import com.gym.auth.dto.UserResponse;
import com.gym.auth.entity.Role;
import com.gym.auth.entity.User;
import com.gym.auth.exception.ApiException;
import com.gym.auth.repository.PasswordResetOtpRepository;
import com.gym.auth.repository.UserRepository;
import com.gym.auth.security.JwtTokenService;
import com.gym.auth.security.JwtTokenService.AccessToken;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

	private static final String INVALID_CREDENTIALS = "Invalid email or password.";

	private final UserRepository userRepository;
	private final PasswordResetOtpRepository otpRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtTokenService jwtTokenService;
	private final Clock clock;

	/**
	 * Hash checked when the email is unknown, so unknown and known emails take a similar amount of time
	 * to answer a login attempt.
	 */
	private final String dummyPasswordHash;

	public AuthService(UserRepository userRepository, PasswordResetOtpRepository otpRepository,
			PasswordEncoder passwordEncoder, JwtTokenService jwtTokenService, Clock clock) {
		this.userRepository = userRepository;
		this.otpRepository = otpRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtTokenService = jwtTokenService;
		this.clock = clock;
		this.dummyPasswordHash = passwordEncoder.encode(UUID.randomUUID().toString());
	}

	/** Public registration. Always creates an active MEMBER; ADMIN and STAFF cannot be requested here. */
	@Transactional
	public UserResponse register(RegisterRequest request) {
		String email = normalizeEmail(request.email());
		if (userRepository.existsByEmail(email)) {
			throw new ApiException(HttpStatus.CONFLICT, "An account with this email already exists.");
		}

		LocalDateTime now = LocalDateTime.now(clock);
		User user = new User();
		user.setFullName(request.fullName().trim());
		user.setEmail(email);
		user.setPasswordHash(passwordEncoder.encode(request.password()));
		user.setPhone(blankToNull(request.phone()));
		user.setAddress(blankToNull(request.address()));
		user.setEmergencyContactName(blankToNull(request.emergencyContactName()));
		user.setEmergencyContactPhone(blankToNull(request.emergencyContactPhone()));
		user.setRole(Role.MEMBER);
		user.setActive(true);
		user.setCreatedAt(now);
		user.setUpdatedAt(now);

		return toResponse(userRepository.save(user));
	}

	@Transactional(readOnly = true)
	public LoginResponse login(LoginRequest request) {
		String email = normalizeEmail(request.email());
		Optional<User> candidate = userRepository.findByEmail(email);

		boolean passwordMatches;
		if (candidate.isPresent()) {
			passwordMatches = passwordEncoder.matches(request.password(), candidate.get().getPasswordHash());
		} else {
			passwordEncoder.matches(request.password(), dummyPasswordHash);
			passwordMatches = false;
		}
		if (candidate.isEmpty() || !passwordMatches) {
			throw new ApiException(HttpStatus.UNAUTHORIZED, INVALID_CREDENTIALS);
		}

		User user = candidate.get();
		// Checked only after the password is verified, so the account status is not revealed to anyone
		// who does not know the password.
		if (!user.isActive()) {
			throw new ApiException(HttpStatus.FORBIDDEN,
					"This account is inactive. Please contact the gym administrator.");
		}

		AccessToken token = jwtTokenService.issueAccessToken(user);
		return new LoginResponse(token.value(), "Bearer", token.expiresInSeconds(), token.expiresAt(),
				toResponse(user));
	}

	/**
	 * Authenticated password change. The user is identified only by the JWT subject. Outstanding
	 * password-reset OTPs are invalidated so they cannot be used after the change.
	 */
	@Transactional
	public void changePassword(Long userId, ChangePasswordRequest request) {
		User user = userRepository.findById(userId)
				.orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Authentication is no longer valid."));
		if (!user.isActive()) {
			throw new ApiException(HttpStatus.FORBIDDEN,
					"This account is inactive. Please contact the gym administrator.");
		}
		if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
			throw new ApiException(HttpStatus.BAD_REQUEST, "Current password is incorrect.");
		}
		if (passwordEncoder.matches(request.newPassword(), user.getPasswordHash())) {
			throw new ApiException(HttpStatus.BAD_REQUEST, "New password must be different from the current password.");
		}

		LocalDateTime now = LocalDateTime.now(clock);
		user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
		user.setUpdatedAt(now);
		userRepository.save(user);
		otpRepository.invalidateActiveOtps(userId, now);
	}

	UserResponse toResponse(User user) {
		return new UserResponse(
				user.getUserId(),
				user.getFullName(),
				user.getEmail(),
				user.getPhone(),
				user.getAddress(),
				user.getRole(),
				user.isActive(),
				user.getCreatedAt());
	}

	static String normalizeEmail(String email) {
		return email.trim().toLowerCase(Locale.ROOT);
	}

	private static String blankToNull(String value) {
		return value == null || value.isBlank() ? null : value.trim();
	}

}

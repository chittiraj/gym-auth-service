package com.gym.auth.controller;

import com.gym.auth.dto.RegisterRequest;
import com.gym.auth.dto.UserResponse;
import com.gym.auth.exception.ApiException;
import com.gym.auth.security.InternalServiceKeyVerifier;
import com.gym.auth.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Account creation for the Management Service. The Management Service checks that the caller is an ADMIN
 * before calling this. This route is not a public registration route: it accepts only the shared service
 * key, never a bearer token. AuthService.register always creates an active MEMBER and BCrypt-hashes the
 * password, so no role can be requested here.
 */
@RestController
@RequestMapping("/api/internal/members")
public class InternalMemberController {

	private final AuthService authService;
	private final InternalServiceKeyVerifier keyVerifier;

	public InternalMemberController(AuthService authService, InternalServiceKeyVerifier keyVerifier) {
		this.authService = authService;
		this.keyVerifier = keyVerifier;
	}

	@PostMapping
	public ResponseEntity<UserResponse> createMember(
			@RequestHeader(value = InternalServiceKeyVerifier.HEADER, required = false) String serviceKey,
			@Valid @RequestBody RegisterRequest request) {
		if (!keyVerifier.matches(serviceKey)) {
			throw new ApiException(HttpStatus.UNAUTHORIZED, "Invalid service credential.");
		}
		return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
	}

}

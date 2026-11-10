package com.gym.auth.controller;

import com.gym.auth.dto.ChangePasswordRequest;
import com.gym.auth.dto.ForgotPasswordRequest;
import com.gym.auth.dto.LoginRequest;
import com.gym.auth.dto.LoginResponse;
import com.gym.auth.dto.MessageResponse;
import com.gym.auth.dto.RegisterRequest;
import com.gym.auth.dto.ResetPasswordRequest;
import com.gym.auth.dto.UserResponse;
import com.gym.auth.dto.VerifyOtpRequest;
import com.gym.auth.dto.VerifyOtpResponse;
import com.gym.auth.exception.ApiException;
import com.gym.auth.service.AuthService;
import com.gym.auth.service.PasswordResetService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

	private final AuthService authService;
	private final PasswordResetService passwordResetService;

	public AuthController(AuthService authService, PasswordResetService passwordResetService) {
		this.authService = authService;
		this.passwordResetService = passwordResetService;
	}

	@PostMapping("/register")
	public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
		return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
	}

	@PostMapping("/login")
	public LoginResponse login(@Valid @RequestBody LoginRequest request) {
		return authService.login(request);
	}

	@PostMapping("/forgot-password")
	public MessageResponse forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
		return passwordResetService.requestOtp(request);
	}

	@PostMapping("/verify-reset-otp")
	public VerifyOtpResponse verifyResetOtp(@Valid @RequestBody VerifyOtpRequest request) {
		return passwordResetService.verifyOtp(request);
	}

	@PostMapping("/reset-password")
	public MessageResponse resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
		return passwordResetService.resetPassword(request);
	}

	/** Identity comes only from the verified JWT subject; no user id is accepted from the client. */
	@PostMapping("/change-password")
	public MessageResponse changePassword(@AuthenticationPrincipal Jwt jwt,
			@Valid @RequestBody ChangePasswordRequest request) {
		authService.changePassword(parseUserId(jwt), request);
		return new MessageResponse("Password changed successfully.");
	}

	private static Long parseUserId(Jwt jwt) {
		try {
			return Long.valueOf(jwt.getSubject());
		} catch (NumberFormatException ex) {
			throw new ApiException(HttpStatus.UNAUTHORIZED, "Authentication is no longer valid.");
		}
	}

}

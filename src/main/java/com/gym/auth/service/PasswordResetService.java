package com.gym.auth.service;

import com.gym.auth.config.PasswordResetProperties;
import com.gym.auth.dto.ForgotPasswordRequest;
import com.gym.auth.dto.MessageResponse;
import com.gym.auth.dto.ResetPasswordRequest;
import com.gym.auth.dto.VerifyOtpRequest;
import com.gym.auth.dto.VerifyOtpResponse;
import com.gym.auth.entity.PasswordResetOtp;
import com.gym.auth.entity.User;
import com.gym.auth.exception.ApiException;
import com.gym.auth.repository.PasswordResetOtpRepository;
import com.gym.auth.repository.UserRepository;
import com.gym.auth.security.JwtTokenService;
import com.gym.auth.security.JwtTokenService.ParsedResetToken;
import com.gym.auth.security.JwtTokenService.ResetToken;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Forgot-password flow: request an OTP by email, verify it, then reset the password with the reset
 * authorization that verification returns.
 */
@Service
public class PasswordResetService {

	private static final Logger log = LoggerFactory.getLogger(PasswordResetService.class);

	static final String GENERIC_REQUEST_MESSAGE =
			"If an account exists for this email, a verification code has been sent.";
	static final String INVALID_OTP = "Invalid or expired verification code.";
	static final String INVALID_RESET = "Invalid or expired password reset authorization.";

	private final UserRepository userRepository;
	private final PasswordResetOtpRepository otpRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtTokenService jwtTokenService;
	private final PasswordResetEmailService emailService;
	private final PasswordResetProperties properties;
	private final Clock clock;
	private final TransactionTemplate transactionTemplate;
	private final SecureRandom secureRandom = new SecureRandom();

	public PasswordResetService(UserRepository userRepository, PasswordResetOtpRepository otpRepository,
			PasswordEncoder passwordEncoder, JwtTokenService jwtTokenService,
			PasswordResetEmailService emailService, PasswordResetProperties properties, Clock clock,
			PlatformTransactionManager transactionManager) {
		this.userRepository = userRepository;
		this.otpRepository = otpRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtTokenService = jwtTokenService;
		this.emailService = emailService;
		this.properties = properties;
		this.clock = clock;
		this.transactionTemplate = new TransactionTemplate(transactionManager);
	}

	/**
	 * Issues an OTP and emails it. The OTP is generated and stored inside a short transaction; the email is
	 * sent afterwards and asynchronously, so the response time does not reveal whether the account exists.
	 * The response is identical in every case, including unknown, inactive or throttled accounts.
	 */
	public MessageResponse requestOtp(ForgotPasswordRequest request) {
		String email = AuthService.normalizeEmail(request.email());
		Optional<IssuedOtp> issued = transactionTemplate.execute(status -> issueOtp(email));
		if (issued != null && issued.isPresent()) {
			IssuedOtp otp = issued.get();
			emailService.sendPasswordResetOtp(otp.userId(), otp.email(), otp.fullName(), otp.code(),
					Duration.ofMillis(properties.otpExpirationMs()).toMinutes());
		}
		return new MessageResponse(GENERIC_REQUEST_MESSAGE);
	}

	@Transactional(noRollbackFor = ApiException.class)
	public VerifyOtpResponse verifyOtp(VerifyOtpRequest request) {
		String email = AuthService.normalizeEmail(request.email());
		User user = userRepository.findByEmail(email)
				.filter(User::isActive)
				.orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, INVALID_OTP));

		LocalDateTime now = LocalDateTime.now(clock);
		PasswordResetOtp otp = otpRepository.findFirstByUserIdAndUsedAtIsNullOrderByOtpIdDesc(user.getUserId())
				.orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, INVALID_OTP));

		// Verifying the same OTP twice must not create a second reset authorization.
		if (otp.getVerifiedAt() != null || !otp.getExpiresAt().isAfter(now)
				|| otp.getAttempts() >= properties.maxAttempts()) {
			throw new ApiException(HttpStatus.BAD_REQUEST, INVALID_OTP);
		}

		if (!passwordEncoder.matches(request.otp(), otp.getOtpHash())) {
			// Persisted before the exception is thrown: noRollbackFor keeps this attempt counter update.
			otp.setAttempts(otp.getAttempts() + 1);
			otpRepository.save(otp);
			throw new ApiException(HttpStatus.BAD_REQUEST, INVALID_OTP);
		}

		otp.setVerifiedAt(now);
		otpRepository.save(otp);

		ResetToken resetToken = jwtTokenService.issueResetToken(user.getUserId(), otp.getOtpId(),
				otp.getExpiresAt().atZone(clock.getZone()).toInstant());
		return new VerifyOtpResponse(
				"Verification successful. Use the reset token to set a new password.",
				resetToken.value(),
				resetToken.expiresAt());
	}

	@Transactional(noRollbackFor = ApiException.class)
	public MessageResponse resetPassword(ResetPasswordRequest request) {
		ParsedResetToken parsed = jwtTokenService.parseResetToken(request.resetToken());

		PasswordResetOtp otp = otpRepository.findByIdForUpdate(parsed.otpId())
				.orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, INVALID_RESET));
		LocalDateTime now = LocalDateTime.now(clock);
		if (!otp.getUserId().equals(parsed.userId())
				|| otp.getVerifiedAt() == null
				|| otp.getUsedAt() != null
				|| !otp.getExpiresAt().isAfter(now)) {
			throw new ApiException(HttpStatus.BAD_REQUEST, INVALID_RESET);
		}

		User user = userRepository.findById(parsed.userId())
				.filter(User::isActive)
				.orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, INVALID_RESET));

		// Password update and OTP consumption happen in this one transaction.
		user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
		user.setUpdatedAt(now);
		userRepository.save(user);

		otp.setUsedAt(now);
		otpRepository.save(otp);
		otpRepository.invalidateActiveOtps(user.getUserId(), now);

		return new MessageResponse("Password has been reset successfully. Please log in with your new password.");
	}

	/** Runs inside the transaction opened by {@link #requestOtp}. The user row lock serialises concurrent requests. */
	private Optional<IssuedOtp> issueOtp(String email) {
		Optional<User> candidate = userRepository.findByEmailForUpdate(email)
				.filter(User::isActive);
		if (candidate.isEmpty()) {
			return Optional.empty();
		}
		User user = candidate.get();
		LocalDateTime now = LocalDateTime.now(clock);

		Optional<PasswordResetOtp> latest = otpRepository.findFirstByUserIdOrderByOtpIdDesc(user.getUserId());
		if (latest.isPresent()
				&& latest.get().getCreatedAt().plusSeconds(properties.resendCooldownSeconds()).isAfter(now)) {
			log.info("OTP request throttled by resend cooldown for user id {}", user.getUserId());
			return Optional.empty();
		}
		long recentRequests = otpRepository.countByUserIdAndCreatedAtAfter(user.getUserId(), now.minusHours(1));
		if (recentRequests >= properties.maxRequestsPerHour()) {
			log.warn("OTP request limit reached for user id {}", user.getUserId());
			return Optional.empty();
		}

		// Older unused OTPs are invalidated so only the newest code can be used.
		otpRepository.invalidateActiveOtps(user.getUserId(), now);

		String code = generateOtp();
		PasswordResetOtp otp = new PasswordResetOtp();
		otp.setUserId(user.getUserId());
		otp.setOtpHash(passwordEncoder.encode(code));
		otp.setAttempts(0);
		otp.setCreatedAt(now);
		otp.setExpiresAt(now.plus(Duration.ofMillis(properties.otpExpirationMs())));
		otpRepository.save(otp);

		return Optional.of(new IssuedOtp(user.getUserId(), user.getEmail(), user.getFullName(), code));
	}

	/** Cryptographically secure six-digit code, zero-padded. */
	String generateOtp() {
		return String.format("%06d", secureRandom.nextInt(1_000_000));
	}

	/** Plain OTP is held only in memory long enough to be emailed. It is never persisted or logged. */
	private record IssuedOtp(Long userId, String email, String fullName, String code) {
	}

}

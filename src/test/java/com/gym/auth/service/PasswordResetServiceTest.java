package com.gym.auth.service;

import static com.gym.auth.support.TestSupport.assertStatus;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.gym.auth.config.PasswordResetProperties;
import com.gym.auth.dto.ForgotPasswordRequest;
import com.gym.auth.dto.MessageResponse;
import com.gym.auth.dto.ResetPasswordRequest;
import com.gym.auth.dto.VerifyOtpRequest;
import com.gym.auth.dto.VerifyOtpResponse;
import com.gym.auth.entity.PasswordResetOtp;
import com.gym.auth.entity.Role;
import com.gym.auth.entity.User;
import com.gym.auth.repository.PasswordResetOtpRepository;
import com.gym.auth.repository.UserRepository;
import com.gym.auth.security.JwtTokenService;
import com.gym.auth.support.TestSupport;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;

@ExtendWith(MockitoExtension.class)
class PasswordResetServiceTest {

	private static final String EMAIL = "test@gmail.com";
	private static final PasswordResetProperties PROPS =
			new PasswordResetProperties(300_000L, 5, 60L, 5);

	@Mock
	UserRepository userRepository;

	@Mock
	PasswordResetOtpRepository otpRepository;

	@Mock
	PasswordResetEmailService emailService;

	@Mock
	PlatformTransactionManager transactionManager;

	private final PasswordEncoder encoder = new BCryptPasswordEncoder(4);
	private final Clock clock = Clock.systemDefaultZone();
	private final JwtTokenService tokens = TestSupport.jwtTokenService(clock);

	private PasswordResetService service;

	@BeforeEach
	void setUp() {
		service = new PasswordResetService(userRepository, otpRepository, encoder, tokens, emailService, PROPS,
				clock, transactionManager);
	}

	private static LocalDateTime now() {
		return LocalDateTime.now();
	}

	private User user(long id, boolean active) {
		User user = new User();
		user.setUserId(id);
		user.setFullName("Test User");
		user.setEmail(EMAIL);
		user.setPasswordHash(encoder.encode("OldPassword@123"));
		user.setRole(Role.MEMBER);
		user.setActive(active);
		user.setCreatedAt(now());
		user.setUpdatedAt(now());
		return user;
	}

	private PasswordResetOtp otp(long otpId, long userId, String code, LocalDateTime expiresAt) {
		PasswordResetOtp otp = new PasswordResetOtp();
		otp.setOtpId(otpId);
		otp.setUserId(userId);
		otp.setOtpHash(encoder.encode(code));
		otp.setExpiresAt(expiresAt);
		otp.setAttempts(0);
		otp.setCreatedAt(now());
		return otp;
	}

	// ---------- Forgot password / OTP generation ----------

	@Test
	void forgotPasswordForActiveUserStoresHashedOtpAndEmailsPlainCode() {
		LocalDateTime before = now();
		when(userRepository.findByEmailForUpdate(EMAIL)).thenReturn(Optional.of(user(7L, true)));
		when(otpRepository.findFirstByUserIdOrderByOtpIdDesc(7L)).thenReturn(Optional.empty());
		when(otpRepository.countByUserIdAndCreatedAtAfter(eq(7L), any(LocalDateTime.class))).thenReturn(0L);

		MessageResponse response = service.requestOtp(new ForgotPasswordRequest(EMAIL));

		assertThat(response.message()).isEqualTo(PasswordResetService.GENERIC_REQUEST_MESSAGE);

		ArgumentCaptor<PasswordResetOtp> saved = ArgumentCaptor.forClass(PasswordResetOtp.class);
		verify(otpRepository).save(saved.capture());
		ArgumentCaptor<String> emailedCode = ArgumentCaptor.forClass(String.class);
		verify(emailService).sendPasswordResetOtp(eq(7L), eq(EMAIL), eq("Test User"), emailedCode.capture(), eq(5L));

		String code = emailedCode.getValue();
		PasswordResetOtp stored = saved.getValue();
		assertThat(code).matches("\\d{6}");
		assertThat(stored.getOtpHash()).startsWith("$2").doesNotContain(code);
		assertThat(encoder.matches(code, stored.getOtpHash())).isTrue();
		assertThat(stored.getExpiresAt())
				.isBetween(before.plusMinutes(4).plusSeconds(59), before.plusMinutes(5).plusSeconds(10));
		assertThat(stored.getAttempts()).isZero();
		assertThat(stored.getVerifiedAt()).isNull();
		assertThat(stored.getUsedAt()).isNull();
		verify(otpRepository).invalidateActiveOtps(eq(7L), any(LocalDateTime.class));
	}

	@Test
	void forgotPasswordForUnknownEmailReturnsGenericResponseWithoutSideEffects() {
		when(userRepository.findByEmailForUpdate(EMAIL)).thenReturn(Optional.empty());

		MessageResponse response = service.requestOtp(new ForgotPasswordRequest(EMAIL));

		assertThat(response.message()).isEqualTo(PasswordResetService.GENERIC_REQUEST_MESSAGE);
		verify(otpRepository, never()).save(any());
		verify(emailService, never()).sendPasswordResetOtp(any(), any(), any(), any(), anyLong());
	}

	@Test
	void forgotPasswordForInactiveAccountIsSilentlyIgnored() {
		when(userRepository.findByEmailForUpdate(EMAIL)).thenReturn(Optional.of(user(7L, false)));

		MessageResponse response = service.requestOtp(new ForgotPasswordRequest(EMAIL));

		assertThat(response.message()).isEqualTo(PasswordResetService.GENERIC_REQUEST_MESSAGE);
		verify(otpRepository, never()).save(any());
		verify(emailService, never()).sendPasswordResetOtp(any(), any(), any(), any(), anyLong());
	}

	@Test
	void resendCooldownSuppressesNewOtpButReturnsSameGenericResponse() {
		when(userRepository.findByEmailForUpdate(EMAIL)).thenReturn(Optional.of(user(7L, true)));
		PasswordResetOtp recent = otp(1L, 7L, "123456", now().plusMinutes(4));
		recent.setCreatedAt(now().minusSeconds(10));
		when(otpRepository.findFirstByUserIdOrderByOtpIdDesc(7L)).thenReturn(Optional.of(recent));

		MessageResponse response = service.requestOtp(new ForgotPasswordRequest(EMAIL));

		assertThat(response.message()).isEqualTo(PasswordResetService.GENERIC_REQUEST_MESSAGE);
		verify(otpRepository, never()).save(any());
		verify(emailService, never()).sendPasswordResetOtp(any(), any(), any(), any(), anyLong());
	}

	@Test
	void hourlyRequestLimitSuppressesNewOtp() {
		when(userRepository.findByEmailForUpdate(EMAIL)).thenReturn(Optional.of(user(7L, true)));
		when(otpRepository.findFirstByUserIdOrderByOtpIdDesc(7L)).thenReturn(Optional.empty());
		when(otpRepository.countByUserIdAndCreatedAtAfter(eq(7L), any(LocalDateTime.class))).thenReturn(5L);

		service.requestOtp(new ForgotPasswordRequest(EMAIL));

		verify(otpRepository, never()).save(any());
		verify(emailService, never()).sendPasswordResetOtp(any(), any(), any(), any(), anyLong());
	}

	@Test
	void generatedOtpsAreSixDigitsIncludingLeadingZeros() {
		for (int i = 0; i < 2_000; i++) {
			assertThat(service.generateOtp()).matches("\\d{6}");
		}
	}

	// ---------- Verify OTP ----------

	@Test
	void incorrectOtpIncrementsAttemptCounter() {
		PasswordResetOtp otp = otp(99L, 7L, "123456", now().plusMinutes(4));
		when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user(7L, true)));
		when(otpRepository.findFirstByUserIdAndUsedAtIsNullOrderByOtpIdDesc(7L)).thenReturn(Optional.of(otp));

		assertStatus(() -> service.verifyOtp(new VerifyOtpRequest(EMAIL, "654321")), HttpStatus.BAD_REQUEST);

		assertThat(otp.getAttempts()).isEqualTo(1);
		assertThat(otp.getVerifiedAt()).isNull();
		verify(otpRepository).save(otp);
	}

	@Test
	void maximumIncorrectAttemptsExhaustTheOtpEvenForTheRightCode() {
		PasswordResetOtp otp = otp(99L, 7L, "123456", now().plusMinutes(4));
		otp.setAttempts(5);
		when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user(7L, true)));
		when(otpRepository.findFirstByUserIdAndUsedAtIsNullOrderByOtpIdDesc(7L)).thenReturn(Optional.of(otp));

		assertStatus(() -> service.verifyOtp(new VerifyOtpRequest(EMAIL, "123456")), HttpStatus.BAD_REQUEST);

		assertThat(otp.getVerifiedAt()).isNull();
	}

	@Test
	void expiredOtpIsRejectedWithoutCountingAnAttempt() {
		PasswordResetOtp otp = otp(99L, 7L, "123456", now().minusMinutes(1));
		when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user(7L, true)));
		when(otpRepository.findFirstByUserIdAndUsedAtIsNullOrderByOtpIdDesc(7L)).thenReturn(Optional.of(otp));

		assertStatus(() -> service.verifyOtp(new VerifyOtpRequest(EMAIL, "123456")), HttpStatus.BAD_REQUEST);

		assertThat(otp.getAttempts()).isZero();
		verify(otpRepository, never()).save(any());
	}

	@Test
	void unknownEmailOnVerifyReturnsSameErrorAsWrongCode() {
		when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

		assertStatus(() -> service.verifyOtp(new VerifyOtpRequest(EMAIL, "123456")), HttpStatus.BAD_REQUEST);
	}

	@Test
	void successfulVerificationSetsVerifiedAtAndReturnsBoundResetToken() {
		PasswordResetOtp otp = otp(99L, 7L, "123456", now().plusMinutes(4));
		when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user(7L, true)));
		when(otpRepository.findFirstByUserIdAndUsedAtIsNullOrderByOtpIdDesc(7L)).thenReturn(Optional.of(otp));

		VerifyOtpResponse response = service.verifyOtp(new VerifyOtpRequest(EMAIL, "123456"));

		assertThat(otp.getVerifiedAt()).isNotNull();
		assertThat(response.resetToken()).isNotBlank();
		JwtTokenService.ParsedResetToken parsed = tokens.parseResetToken(response.resetToken());
		assertThat(parsed.userId()).isEqualTo(7L);
		assertThat(parsed.otpId()).isEqualTo(99L);
	}

	@Test
	void repeatedVerificationOfSameOtpDoesNotCreateSecondResetAuthorization() {
		PasswordResetOtp otp = otp(99L, 7L, "123456", now().plusMinutes(4));
		when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user(7L, true)));
		when(otpRepository.findFirstByUserIdAndUsedAtIsNullOrderByOtpIdDesc(7L)).thenReturn(Optional.of(otp));

		service.verifyOtp(new VerifyOtpRequest(EMAIL, "123456"));

		assertStatus(() -> service.verifyOtp(new VerifyOtpRequest(EMAIL, "123456")), HttpStatus.BAD_REQUEST);
	}

	// ---------- Reset password ----------

	@Test
	void resetWithoutSuccessfulVerificationIsRejected() {
		PasswordResetOtp unverified = otp(99L, 7L, "123456", now().plusMinutes(4));
		String token = tokens.issueResetToken(7L, 99L, java.time.Instant.now().plus(Duration.ofMinutes(4))).value();
		when(otpRepository.findByIdForUpdate(99L)).thenReturn(Optional.of(unverified));

		User user = user(7L, true);
		assertStatus(() -> service.resetPassword(new ResetPasswordRequest(token, "NewPassword@123")),
				HttpStatus.BAD_REQUEST);

		assertThat(encoder.matches("OldPassword@123", user.getPasswordHash())).isTrue();
		verify(userRepository, never()).save(any());
	}

	@Test
	void resetAfterVerificationUpdatesPasswordConsumesOtpAndInvalidatesOthers() {
		PasswordResetOtp otp = otp(99L, 7L, "123456", now().plusMinutes(4));
		otp.setVerifiedAt(now());
		User user = user(7L, true);
		String token = tokens.issueResetToken(7L, 99L, java.time.Instant.now().plus(Duration.ofMinutes(4))).value();
		when(otpRepository.findByIdForUpdate(99L)).thenReturn(Optional.of(otp));
		when(userRepository.findById(7L)).thenReturn(Optional.of(user));

		MessageResponse response = service.resetPassword(new ResetPasswordRequest(token, "NewPassword@123"));

		assertThat(response.message()).contains("reset successfully");
		assertThat(encoder.matches("NewPassword@123", user.getPasswordHash())).isTrue();
		assertThat(otp.getUsedAt()).isNotNull();
		verify(userRepository).save(user);
		verify(otpRepository).invalidateActiveOtps(eq(7L), any(LocalDateTime.class));
	}

	@Test
	void resetTokenCannotBeReplayedAfterSuccess() {
		PasswordResetOtp otp = otp(99L, 7L, "123456", now().plusMinutes(4));
		otp.setVerifiedAt(now());
		User user = user(7L, true);
		String token = tokens.issueResetToken(7L, 99L, java.time.Instant.now().plus(Duration.ofMinutes(4))).value();
		when(otpRepository.findByIdForUpdate(99L)).thenReturn(Optional.of(otp));
		when(userRepository.findById(7L)).thenReturn(Optional.of(user));
		service.resetPassword(new ResetPasswordRequest(token, "NewPassword@123"));

		assertStatus(() -> service.resetPassword(new ResetPasswordRequest(token, "AnotherPass@1")),
				HttpStatus.BAD_REQUEST);
	}

	@Test
	void resetTokenBoundToAnotherUserIsRejected() {
		PasswordResetOtp otp = otp(99L, 7L, "123456", now().plusMinutes(4));
		otp.setVerifiedAt(now());
		String token = tokens.issueResetToken(8L, 99L, java.time.Instant.now().plus(Duration.ofMinutes(4))).value();
		when(otpRepository.findByIdForUpdate(99L)).thenReturn(Optional.of(otp));

		assertStatus(() -> service.resetPassword(new ResetPasswordRequest(token, "NewPassword@123")),
				HttpStatus.BAD_REQUEST);
		verify(userRepository, never()).save(any());
	}

	@Test
	void resetWithExpiredOtpIsRejectedEvenWhenTokenIsStillValid() {
		PasswordResetOtp otp = otp(99L, 7L, "123456", now().minusMinutes(1));
		otp.setVerifiedAt(now().minusMinutes(2));
		String token = tokens.issueResetToken(7L, 99L, java.time.Instant.now().plus(Duration.ofMinutes(4))).value();
		when(otpRepository.findByIdForUpdate(99L)).thenReturn(Optional.of(otp));

		assertStatus(() -> service.resetPassword(new ResetPasswordRequest(token, "NewPassword@123")),
				HttpStatus.BAD_REQUEST);
		verify(userRepository, never()).save(any());
	}

	@Test
	void accessTokenCannotBeUsedToResetPassword() {
		User user = user(7L, true);
		String accessToken = tokens.issueAccessToken(user).value();

		assertStatus(() -> service.resetPassword(new ResetPasswordRequest(accessToken, "NewPassword@123")),
				HttpStatus.BAD_REQUEST);
		verify(userRepository, never()).save(any());
	}

	// ---------- Email content ----------

	@Test
	void otpEmailTemplateEscapesNameAndStatesExpiry() {
		String html = OtpEmailTemplate.html("<script>alert(1)</script>", "123456", 5);
		String text = OtpEmailTemplate.plainText("Asha", "123456", 5);

		assertThat(html).doesNotContain("<script>").contains("&lt;script&gt;").contains("123456")
				.contains("5 minutes");
		assertThat(text).contains("Your verification code is: 123456").contains("expires in 5 minutes");
		assertThat(text).contains("if you did not request");
	}

}

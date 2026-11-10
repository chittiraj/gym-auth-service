package com.gym.auth.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.gym.auth.config.AppConfig;
import com.gym.auth.config.JwtConfig;
import com.gym.auth.config.SecurityConfig;
import com.gym.auth.entity.PasswordResetOtp;
import com.gym.auth.entity.Role;
import com.gym.auth.entity.User;
import com.gym.auth.repository.PasswordResetOtpRepository;
import com.gym.auth.repository.UserRepository;
import com.gym.auth.security.JwtTokenService;
import com.gym.auth.service.AuthService;
import com.gym.auth.service.PasswordResetEmailService;
import com.gym.auth.service.PasswordResetService;
import com.gym.auth.support.TestSupport;
import com.jayway.jsonpath.JsonPath;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * HTTP-level tests of the authentication endpoints. The controller, security filter chain, validation,
 * services and real JWT handling are all active. Only the database repositories and SMTP are mocked.
 */
@WebMvcTest(AuthController.class)
@Import({AppConfig.class, SecurityConfig.class, JwtConfig.class, AuthService.class, PasswordResetService.class,
		JwtTokenService.class})
class AuthControllerWebTest {

	private static final String EMAIL = "test@gmail.com";
	private static final String OLD_PASSWORD = "OldPassword@123";
	private static final String NEW_PASSWORD = "NewPassword@123";

	@Autowired
	MockMvc mockMvc;

	@Autowired
	JwtTokenService jwtTokenService;

	@Autowired
	PasswordEncoder passwordEncoder;

	@MockitoBean
	UserRepository userRepository;

	@MockitoBean
	PasswordResetOtpRepository otpRepository;

	@MockitoBean
	PasswordResetEmailService emailService;

	@MockitoBean
	PlatformTransactionManager transactionManager;

	@DynamicPropertySource
	static void jwtSecret(DynamicPropertyRegistry registry) {
		registry.add("app.jwt.secret", () -> TestSupport.JWT_SECRET);
	}

	private User user;

	@BeforeEach
	void setUp() {
		user = new User();
		user.setUserId(7L);
		user.setFullName("Test User");
		user.setEmail(EMAIL);
		user.setPasswordHash(passwordEncoder.encode(OLD_PASSWORD));
		user.setRole(Role.MEMBER);
		user.setActive(true);
		user.setCreatedAt(LocalDateTime.now());
		user.setUpdatedAt(LocalDateTime.now());
	}

	private ResultActions postJson(String path, String json) throws Exception {
		return mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(json));
	}

	private ResultActions postJsonWithBearer(String path, String json, String token) throws Exception {
		return mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(json)
				.header("Authorization", "Bearer " + token));
	}

	private static String registerJson(String password, String role) {
		return """
				{"fullName":"Test User","email":"test@gmail.com","password":"%s","phone":"9876543210",
				 "address":"Hyderabad","emergencyContactName":"Emergency Contact","emergencyContactPhone":"9876543211",
				 "role":"%s"}""".formatted(password, role);
	}

	private static String loginJson(String password) {
		return "{\"email\":\"test@gmail.com\",\"password\":\"" + password + "\"}";
	}

	// ---------- Registration ----------

	@Test
	void registerCreatesActiveMemberAndNeverReturnsPasswordHash() throws Exception {
		when(userRepository.existsByEmail(EMAIL)).thenReturn(false);
		when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
			User saved = invocation.getArgument(0);
			saved.setUserId(1L);
			return saved;
		});

		postJson("/api/auth/register", registerJson("Test@123", "ADMIN"))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.role").value("MEMBER"))
				.andExpect(jsonPath("$.isActive").value(true))
				.andExpect(jsonPath("$.passwordHash").doesNotExist())
				.andExpect(jsonPath("$.password").doesNotExist())
				.andExpect(content().string(not(containsString("$2a$"))));

		ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
		verify(userRepository).save(saved.capture());
		assertThat(saved.getValue().getRole()).isEqualTo(Role.MEMBER);
	}

	@Test
	void registerRejectsDuplicateEmail() throws Exception {
		when(userRepository.existsByEmail(EMAIL)).thenReturn(true);

		postJson("/api/auth/register", registerJson("Test@123", "MEMBER"))
				.andExpect(status().isConflict());
	}

	@Test
	void registerRejectsWeakPasswordWithFieldError() throws Exception {
		postJson("/api/auth/register", registerJson("weak", "MEMBER"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.fieldErrors.password").exists());
		verify(userRepository, never()).save(any());
	}

	@Test
	void registerRejectsInvalidEmail() throws Exception {
		String body = registerJson("Test@123", "MEMBER").replace(EMAIL, "not-an-email");

		postJson("/api/auth/register", body).andExpect(status().isBadRequest());
	}

	// ---------- Login ----------

	@Test
	void loginReturnsBearerTokenWithoutPasswordData() throws Exception {
		when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));

		String body = postJson("/api/auth/login", loginJson(OLD_PASSWORD))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.tokenType").value("Bearer"))
				.andExpect(jsonPath("$.user.passwordHash").doesNotExist())
				.andReturn().getResponse().getContentAsString();

		String token = JsonPath.read(body, "$.accessToken");
		assertThat(TestSupport.accessDecoder().decode(token).getSubject()).isEqualTo("7");
	}

	@Test
	void loginRejectsWrongPassword() throws Exception {
		when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));

		postJson("/api/auth/login", loginJson("Wrong@123")).andExpect(status().isUnauthorized());
	}

	@Test
	void loginRejectsInactiveAccount() throws Exception {
		user.setActive(false);
		when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));

		postJson("/api/auth/login", loginJson(OLD_PASSWORD)).andExpect(status().isForbidden());
	}

	// ---------- Forgot password ----------

	@Test
	void forgotPasswordForUnknownEmailReturnsGenericSuccess() throws Exception {
		when(userRepository.findByEmailForUpdate(EMAIL)).thenReturn(Optional.empty());

		postJson("/api/auth/forgot-password", "{\"email\":\"test@gmail.com\"}")
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.message").value(
						"If an account exists for this email, a verification code has been sent."))
				.andExpect(jsonPath("$.otp").doesNotExist());
		verify(otpRepository, never()).save(any());
	}

	@Test
	void forgotPasswordNeverReturnsTheOtpInTheResponse() throws Exception {
		when(userRepository.findByEmailForUpdate(EMAIL)).thenReturn(Optional.of(user));
		when(otpRepository.findFirstByUserIdOrderByOtpIdDesc(7L)).thenReturn(Optional.empty());

		String body = postJson("/api/auth/forgot-password", "{\"email\":\"test@gmail.com\"}")
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();

		ArgumentCaptor<String> code = ArgumentCaptor.forClass(String.class);
		verify(emailService).sendPasswordResetOtp(eq(7L), eq(EMAIL), eq("Test User"), code.capture(), anyLong());
		assertThat(body).doesNotContain(code.getValue());
	}

	// ---------- Verify OTP and reset password ----------

	@Test
	void verifyOtpRejectsMalformedCode() throws Exception {
		postJson("/api/auth/verify-reset-otp", "{\"email\":\"test@gmail.com\",\"otp\":\"12\"}")
				.andExpect(status().isBadRequest());
	}

	@Test
	void verifyOtpWithWrongCodeReturnsNoResetToken() throws Exception {
		PasswordResetOtp otp = new PasswordResetOtp();
		otp.setOtpId(99L);
		otp.setUserId(7L);
		otp.setOtpHash(passwordEncoder.encode("123456"));
		otp.setExpiresAt(LocalDateTime.now().plusMinutes(4));
		otp.setCreatedAt(LocalDateTime.now());
		when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
		when(otpRepository.findFirstByUserIdAndUsedAtIsNullOrderByOtpIdDesc(7L)).thenReturn(Optional.of(otp));

		postJson("/api/auth/verify-reset-otp", "{\"email\":\"test@gmail.com\",\"otp\":\"654321\"}")
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.resetToken").doesNotExist());
	}

	@Test
	void resetPasswordRejectsGarbageToken() throws Exception {
		postJson("/api/auth/reset-password",
				"{\"resetToken\":\"not-a-token\",\"newPassword\":\"" + NEW_PASSWORD + "\"}")
				.andExpect(status().isBadRequest());
	}

	@Test
	void resetPasswordRequiresToken() throws Exception {
		postJson("/api/auth/reset-password", "{\"newPassword\":\"" + NEW_PASSWORD + "\"}")
				.andExpect(status().isBadRequest());
	}

	/**
	 * Full forgot-password journey over HTTP with stateful OTP storage: request, verify, reset, then log
	 * in with the new password. Also checks that the reset token cannot be replayed.
	 */
	@Test
	void forgotPasswordJourneyEndToEndResetsPassword() throws Exception {
		AtomicReference<PasswordResetOtp> storedOtp = new AtomicReference<>();
		when(userRepository.findByEmailForUpdate(EMAIL)).thenReturn(Optional.of(user));
		when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
		when(userRepository.findById(7L)).thenReturn(Optional.of(user));
		when(otpRepository.save(any(PasswordResetOtp.class))).thenAnswer(invocation -> {
			PasswordResetOtp otp = invocation.getArgument(0);
			if (otp.getOtpId() == null) {
				otp.setOtpId(99L);
			}
			storedOtp.set(otp);
			return otp;
		});
		when(otpRepository.findFirstByUserIdOrderByOtpIdDesc(anyLong()))
				.thenAnswer(invocation -> Optional.ofNullable(storedOtp.get()));
		when(otpRepository.findFirstByUserIdAndUsedAtIsNullOrderByOtpIdDesc(anyLong()))
				.thenAnswer(invocation -> Optional.ofNullable(storedOtp.get())
						.filter(otp -> otp.getUsedAt() == null));
		when(otpRepository.findByIdForUpdate(anyLong()))
				.thenAnswer(invocation -> Optional.ofNullable(storedOtp.get()));
		when(otpRepository.invalidateActiveOtps(anyLong(), any(LocalDateTime.class)))
				.thenAnswer(invocation -> {
					PasswordResetOtp otp = storedOtp.get();
					if (otp != null && otp.getUsedAt() == null) {
						otp.setUsedAt(invocation.getArgument(1));
						return 1;
					}
					return 0;
				});

		// 1. Request the OTP.
		postJson("/api/auth/forgot-password", "{\"email\":\"test@gmail.com\"}").andExpect(status().isOk());
		ArgumentCaptor<String> emailed = ArgumentCaptor.forClass(String.class);
		verify(emailService).sendPasswordResetOtp(eq(7L), eq(EMAIL), eq("Test User"), emailed.capture(), anyLong());
		String code = emailed.getValue();

		// 2. Reset attempted before verification must fail.
		String unverifiedToken = jwtTokenService.issueResetToken(7L, 99L, Instant.now().plus(Duration.ofMinutes(4)))
				.value();
		postJson("/api/auth/reset-password",
				"{\"resetToken\":\"" + unverifiedToken + "\",\"newPassword\":\"" + NEW_PASSWORD + "\"}")
				.andExpect(status().isBadRequest());
		assertThat(passwordEncoder.matches(OLD_PASSWORD, user.getPasswordHash())).isTrue();

		// 3. Verify the OTP and receive the reset authorization.
		String verifyBody = postJson("/api/auth/verify-reset-otp",
				"{\"email\":\"test@gmail.com\",\"otp\":\"" + code + "\"}")
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();
		String resetToken = JsonPath.read(verifyBody, "$.resetToken");

		// 4. Reset the password.
		postJson("/api/auth/reset-password",
				"{\"resetToken\":\"" + resetToken + "\",\"newPassword\":\"" + NEW_PASSWORD + "\"}")
				.andExpect(status().isOk());

		// 5. The reset token and the OTP are single-use.
		postJson("/api/auth/reset-password",
				"{\"resetToken\":\"" + resetToken + "\",\"newPassword\":\"Another@Pass1\"}")
				.andExpect(status().isBadRequest());

		// 6. The new password works and the old one no longer does.
		postJson("/api/auth/login", loginJson(NEW_PASSWORD)).andExpect(status().isOk());
		postJson("/api/auth/login", loginJson(OLD_PASSWORD)).andExpect(status().isUnauthorized());
	}

	// ---------- Change password ----------

	@Test
	void changePasswordWithoutTokenIsUnauthorized() throws Exception {
		postJson("/api/auth/change-password",
				"{\"currentPassword\":\"" + OLD_PASSWORD + "\",\"newPassword\":\"" + NEW_PASSWORD + "\"}")
				.andExpect(status().isUnauthorized());
	}

	@Test
	void changePasswordWithMalformedTokenIsUnauthorized() throws Exception {
		postJsonWithBearer("/api/auth/change-password",
				"{\"currentPassword\":\"" + OLD_PASSWORD + "\",\"newPassword\":\"" + NEW_PASSWORD + "\"}",
				"not.a.jwt")
				.andExpect(status().isUnauthorized());
	}

	@Test
	void changePasswordRejectsResetTokenAsBearerCredential() throws Exception {
		String resetToken = jwtTokenService.issueResetToken(7L, 99L, Instant.now().plus(Duration.ofMinutes(4)))
				.value();

		postJsonWithBearer("/api/auth/change-password",
				"{\"currentPassword\":\"" + OLD_PASSWORD + "\",\"newPassword\":\"" + NEW_PASSWORD + "\"}",
				resetToken)
				.andExpect(status().isUnauthorized());
	}

	@Test
	void changePasswordWithValidTokenUpdatesPasswordAndInvalidatesOtps() throws Exception {
		when(userRepository.findById(7L)).thenReturn(Optional.of(user));
		String accessToken = jwtTokenService.issueAccessToken(user).value();

		postJsonWithBearer("/api/auth/change-password",
				"{\"currentPassword\":\"" + OLD_PASSWORD + "\",\"newPassword\":\"" + NEW_PASSWORD + "\"}",
				accessToken)
				.andExpect(status().isOk());

		assertThat(passwordEncoder.matches(NEW_PASSWORD, user.getPasswordHash())).isTrue();
		verify(otpRepository).invalidateActiveOtps(eq(7L), any(LocalDateTime.class));
	}

	@Test
	void changePasswordWithIncorrectCurrentPasswordIsRejected() throws Exception {
		when(userRepository.findById(7L)).thenReturn(Optional.of(user));
		String accessToken = jwtTokenService.issueAccessToken(user).value();

		postJsonWithBearer("/api/auth/change-password",
				"{\"currentPassword\":\"Wrong@123\",\"newPassword\":\"" + NEW_PASSWORD + "\"}", accessToken)
				.andExpect(status().isBadRequest());
		verify(userRepository, never()).save(any());
	}

}

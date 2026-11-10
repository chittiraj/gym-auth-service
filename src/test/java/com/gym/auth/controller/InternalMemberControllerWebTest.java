package com.gym.auth.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.gym.auth.config.AppConfig;
import com.gym.auth.config.JwtConfig;
import com.gym.auth.config.SecurityConfig;
import com.gym.auth.entity.Role;
import com.gym.auth.entity.User;
import com.gym.auth.repository.PasswordResetOtpRepository;
import com.gym.auth.repository.UserRepository;
import com.gym.auth.security.InternalServiceKeyVerifier;
import com.gym.auth.security.JwtTokenService;
import com.gym.auth.service.AuthService;
import com.gym.auth.support.TestSupport;
import java.time.LocalDateTime;
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
 * HTTP tests for the internal account-creation route. The real security chain, service key check and
 * AuthService (BCrypt and the MEMBER rule) are active. Only the repositories are mocked.
 */
@WebMvcTest(InternalMemberController.class)
@Import({AppConfig.class, SecurityConfig.class, JwtConfig.class, AuthService.class, JwtTokenService.class,
		InternalServiceKeyVerifier.class})
class InternalMemberControllerWebTest {

	static final String SERVICE_KEY = "internal-test-key-that-is-long-enough-for-the-check-0123456789";
	private static final String PATH = "/api/internal/members";
	private static final String PASSWORD = "Member@123";

	@Autowired
	MockMvc mockMvc;

	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	JwtTokenService jwtTokenService;

	@MockitoBean
	UserRepository userRepository;

	@MockitoBean
	PasswordResetOtpRepository otpRepository;

	@MockitoBean
	PlatformTransactionManager transactionManager;

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) {
		registry.add("app.jwt.secret", () -> TestSupport.JWT_SECRET);
		registry.add("app.internal.service-key", () -> SERVICE_KEY);
	}

	private static String body(String extraRoleField) {
		return """
				{%s"fullName":"New Member","email":"new@gmail.com","password":"%s","phone":"9876543210",
				 "address":"Hyderabad","emergencyContactName":"Asha","emergencyContactPhone":"9123456780"}"""
				.formatted(extraRoleField, PASSWORD);
	}

	private ResultActions postWithKey(String key, String json) throws Exception {
		var request = post(PATH).contentType(MediaType.APPLICATION_JSON).content(json);
		if (key != null) {
			request.header(InternalServiceKeyVerifier.HEADER, key);
		}
		return mockMvc.perform(request);
	}

	// ---------- Service key ----------

	@Test
	void missingServiceKeyIsUnauthorizedAndNothingIsSaved() throws Exception {
		postWithKey(null, body("")).andExpect(status().isUnauthorized());
		verify(userRepository, never()).save(any());
	}

	@Test
	void wrongServiceKeyIsUnauthorized() throws Exception {
		postWithKey("not-the-right-key", body("")).andExpect(status().isUnauthorized());
		verify(userRepository, never()).save(any());
	}

	@Test
	void bearerTokenIsNotAcceptedInPlaceOfServiceKey() throws Exception {
		User admin = new User();
		admin.setUserId(1L);
		admin.setFullName("Admin");
		admin.setEmail("admin@gmail.com");
		admin.setPasswordHash("unused");
		admin.setRole(Role.ADMIN);
		admin.setActive(true);
		admin.setCreatedAt(LocalDateTime.now());
		admin.setUpdatedAt(LocalDateTime.now());
		String adminToken = jwtTokenService.issueAccessToken(admin).value();

		mockMvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content(body(""))
						.header("Authorization", "Bearer " + adminToken))
				.andExpect(status().isUnauthorized());
		verify(userRepository, never()).save(any());
	}

	// ---------- Account creation ----------

	@Test
	void validServiceKeyCreatesMemberEvenIfCallerRequestsAnotherRole() throws Exception {
		when(userRepository.existsByEmail("new@gmail.com")).thenReturn(false);
		when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
			User saved = invocation.getArgument(0);
			saved.setUserId(42L);
			return saved;
		});

		postWithKey(SERVICE_KEY, body("\"role\":\"ADMIN\","))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.userId").value(42))
				.andExpect(jsonPath("$.role").value("MEMBER"))
				.andExpect(jsonPath("$.isActive").value(true))
				.andExpect(jsonPath("$.passwordHash").doesNotExist());

		ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
		verify(userRepository).save(saved.capture());
		assertThat(saved.getValue().getRole()).isEqualTo(Role.MEMBER);
		assertThat(saved.getValue().getPasswordHash()).isNotEqualTo(PASSWORD);
		assertThat(passwordEncoder.matches(PASSWORD, saved.getValue().getPasswordHash())).isTrue();
	}

	@Test
	void duplicateEmailIsConflict() throws Exception {
		when(userRepository.existsByEmail("new@gmail.com")).thenReturn(true);

		postWithKey(SERVICE_KEY, body("")).andExpect(status().isConflict());
		verify(userRepository, never()).save(any());
	}

	@Test
	void weakPasswordIsValidationErrorEvenWithValidKey() throws Exception {
		String weak = body("").replace(PASSWORD, "weak");

		postWithKey(SERVICE_KEY, weak)
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.fieldErrors.password").exists());
		verify(userRepository, never()).save(any());
	}

}

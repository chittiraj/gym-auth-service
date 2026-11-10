package com.gym.auth.service;

import static com.gym.auth.support.TestSupport.assertStatus;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.gym.auth.dto.ChangePasswordRequest;
import com.gym.auth.dto.LoginRequest;
import com.gym.auth.dto.LoginResponse;
import com.gym.auth.dto.RegisterRequest;
import com.gym.auth.dto.UserResponse;
import com.gym.auth.entity.Role;
import com.gym.auth.entity.User;
import com.gym.auth.repository.PasswordResetOtpRepository;
import com.gym.auth.repository.UserRepository;
import com.gym.auth.security.JwtTokenService;
import com.gym.auth.support.TestSupport;
import java.lang.reflect.RecordComponent;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

	@Mock
	UserRepository userRepository;

	@Mock
	PasswordResetOtpRepository otpRepository;

	/** Low BCrypt cost keeps the unit tests fast. The production encoder uses strength 12. */
	private final PasswordEncoder encoder = new BCryptPasswordEncoder(4);
	private final Clock clock = Clock.systemDefaultZone();
	private final JwtDecoder decoder = TestSupport.accessDecoder();

	private AuthService service;

	@BeforeEach
	void setUp() {
		JwtTokenService tokens = TestSupport.jwtTokenService(clock);
		service = new AuthService(userRepository, otpRepository, encoder, tokens, clock);
	}

	private User user(long id, String rawPassword, boolean active) {
		User user = new User();
		user.setUserId(id);
		user.setFullName("Test User");
		user.setEmail("test@gmail.com");
		user.setPasswordHash(encoder.encode(rawPassword));
		user.setRole(Role.MEMBER);
		user.setActive(active);
		user.setCreatedAt(LocalDateTime.now());
		user.setUpdatedAt(LocalDateTime.now());
		return user;
	}

	private static RegisterRequest registerRequest(String email) {
		return new RegisterRequest("Test User", email, "Test@123", "9876543210", "Hyderabad",
				"Emergency Contact", "9876543211");
	}

	@Test
	void registerStoresBcryptHashAssignsMemberAndActivatesAccount() {
		when(userRepository.existsByEmail("test@gmail.com")).thenReturn(false);
		when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
			User saved = invocation.getArgument(0);
			saved.setUserId(1L);
			return saved;
		});

		UserResponse response = service.register(registerRequest("  Test@GMAIL.com "));

		ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
		verify(userRepository).save(captor.capture());
		User saved = captor.getValue();
		assertThat(saved.getPasswordHash()).startsWith("$2").isNotEqualTo("Test@123");
		assertThat(encoder.matches("Test@123", saved.getPasswordHash())).isTrue();
		assertThat(saved.getRole()).isEqualTo(Role.MEMBER);
		assertThat(saved.isActive()).isTrue();
		assertThat(saved.getEmail()).isEqualTo("test@gmail.com");
		assertThat(response.userId()).isEqualTo(1L);
		assertThat(response.role()).isEqualTo(Role.MEMBER);
	}

	@Test
	void registerRejectsDuplicateEmail() {
		when(userRepository.existsByEmail("test@gmail.com")).thenReturn(true);

		assertStatus(() -> service.register(registerRequest("test@gmail.com")), HttpStatus.CONFLICT);
		verify(userRepository, never()).save(any());
	}

	@Test
	void userResponseHasNoPasswordField() {
		List<String> components = Arrays.stream(UserResponse.class.getRecordComponents())
				.map(RecordComponent::getName)
				.toList();

		assertThat(components).noneMatch(name -> name.toLowerCase().contains("password"));
	}

	@Test
	void loginReturnsBearerTokenForCorrectPassword() {
		when(userRepository.findByEmail("test@gmail.com")).thenReturn(Optional.of(user(7L, "Test@123", true)));

		LoginResponse response = service.login(new LoginRequest("test@gmail.com", "Test@123"));

		assertThat(response.tokenType()).isEqualTo("Bearer");
		assertThat(response.expiresIn()).isEqualTo(1800L);
		assertThat(response.user().userId()).isEqualTo(7L);
		assertThat(response.user().email()).isEqualTo("test@gmail.com");

		Jwt jwt = decoder.decode(response.accessToken());
		assertThat(jwt.getSubject()).isEqualTo("7");
		assertThat(jwt.getClaimAsString("role")).isEqualTo("MEMBER");
	}

	@Test
	void loginRejectsIncorrectPassword() {
		when(userRepository.findByEmail("test@gmail.com")).thenReturn(Optional.of(user(7L, "Test@123", true)));

		assertStatus(() -> service.login(new LoginRequest("test@gmail.com", "Wrong@123")), HttpStatus.UNAUTHORIZED);
	}

	@Test
	void loginRejectsUnknownEmailWithSameStatusAsWrongPassword() {
		when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

		assertStatus(() -> service.login(new LoginRequest("nobody@gmail.com", "Test@123")), HttpStatus.UNAUTHORIZED);
	}

	@Test
	void loginRejectsInactiveUserWhoKnowsThePassword() {
		when(userRepository.findByEmail("test@gmail.com")).thenReturn(Optional.of(user(7L, "Test@123", false)));

		assertStatus(() -> service.login(new LoginRequest("test@gmail.com", "Test@123")), HttpStatus.FORBIDDEN);
	}

	@Test
	void changePasswordUpdatesHashAndInvalidatesOutstandingOtps() {
		User user = user(7L, "OldPassword@123", true);
		when(userRepository.findById(7L)).thenReturn(Optional.of(user));

		service.changePassword(7L, new ChangePasswordRequest("OldPassword@123", "NewPassword@123"));

		assertThat(encoder.matches("NewPassword@123", user.getPasswordHash())).isTrue();
		assertThat(encoder.matches("OldPassword@123", user.getPasswordHash())).isFalse();
		verify(userRepository).save(user);
		verify(otpRepository).invalidateActiveOtps(eq(7L), any(LocalDateTime.class));
	}

	@Test
	void changePasswordRejectsIncorrectCurrentPasswordWithoutSideEffects() {
		when(userRepository.findById(7L)).thenReturn(Optional.of(user(7L, "OldPassword@123", true)));

		assertStatus(() -> service.changePassword(7L, new ChangePasswordRequest("Wrong@123", "NewPassword@123")),
				HttpStatus.BAD_REQUEST);
		verify(userRepository, never()).save(any());
		verify(otpRepository, never()).invalidateActiveOtps(any(), any());
	}

	@Test
	void changePasswordRejectsReusingCurrentPassword() {
		when(userRepository.findById(7L)).thenReturn(Optional.of(user(7L, "OldPassword@123", true)));

		assertStatus(() -> service.changePassword(7L, new ChangePasswordRequest("OldPassword@123", "OldPassword@123")),
				HttpStatus.BAD_REQUEST);
		verify(userRepository, never()).save(any());
	}

}

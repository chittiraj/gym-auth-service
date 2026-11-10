package com.gym.auth.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.gym.auth.config.JwtConfig;
import com.gym.auth.entity.Role;
import com.gym.auth.entity.User;
import com.gym.auth.exception.ApiException;
import com.gym.auth.support.TestSupport;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

class JwtTokenServiceTest {

	private static final String ISSUER = TestSupport.ISSUER;

	private final JwtDecoder decoder = TestSupport.accessDecoder();
	private final JwtTokenService service = TestSupport.jwtTokenService(Clock.systemDefaultZone());

	private static User member(long id) {
		User user = new User();
		user.setUserId(id);
		user.setEmail("test@gmail.com");
		user.setRole(Role.MEMBER);
		user.setActive(true);
		return user;
	}

	@Test
	void accessTokenCarriesSubjectRoleIssuerAndExpiry() {
		User user = member(42L);

		Jwt jwt = decoder.decode(service.issueAccessToken(user).value());

		assertThat(jwt.getSubject()).isEqualTo("42");
		assertThat(jwt.getClaimAsString("role")).isEqualTo("MEMBER");
		assertThat(jwt.getClaimAsString("email")).isEqualTo("test@gmail.com");
		assertThat(jwt.getClaimAsString("iss")).isEqualTo(ISSUER);
		assertThat(Duration.between(jwt.getIssuedAt(), jwt.getExpiresAt())).isEqualTo(Duration.ofMinutes(30));
	}

	@Test
	void accessTokenExpiresInSecondsMatchingConfiguration() {
		JwtTokenService.AccessToken token = service.issueAccessToken(member(1L));

		assertThat(token.expiresInSeconds()).isEqualTo(1800);
	}

	@Test
	void expiredTokenIsRejected() {
		Clock twoHoursAgo = Clock.fixed(Instant.now().minus(Duration.ofHours(2)), ZoneOffset.UTC);
		String expired = TestSupport.jwtTokenService(twoHoursAgo).issueAccessToken(member(1L)).value();

		assertThatThrownBy(() -> decoder.decode(expired)).isInstanceOf(JwtException.class);
	}

	@Test
	void tokenWithIncorrectIssuerIsRejected() {
		String foreign = TestSupport.sign(TestSupport.key(), claims("some-other-service", "1", "MEMBER", null));

		assertThatThrownBy(() -> decoder.decode(foreign)).isInstanceOf(JwtException.class);
	}

	@Test
	void tokenSignedWithDifferentSecretIsRejected() {
		SecretKey otherKey = JwtConfig.buildSecretKey("another-secret-that-is-at-least-32-bytes-long-xyz");
		String forged = TestSupport.sign(otherKey, claims(ISSUER, "1", "ADMIN", null));

		assertThatThrownBy(() -> decoder.decode(forged)).isInstanceOf(JwtException.class);
	}

	@Test
	void tokenWithNonNumericSubjectIsRejected() {
		String token = TestSupport.sign(TestSupport.key(), claims(ISSUER, "not-a-number", "MEMBER", null));

		assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class);
	}

	@Test
	void tokenWithUnknownRoleIsRejected() {
		String token = TestSupport.sign(TestSupport.key(), claims(ISSUER, "1", "SUPERUSER", null));

		assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class);
	}

	@Test
	void resetTokenCannotBeUsedAsAccessToken() {
		String resetToken = service.issueResetToken(1L, 99L, Instant.now().plus(Duration.ofMinutes(5))).value();

		assertThatThrownBy(() -> decoder.decode(resetToken)).isInstanceOf(JwtException.class);
	}

	@Test
	void accessTokenCannotBeUsedAsResetToken() {
		String accessToken = service.issueAccessToken(member(1L)).value();

		assertThatThrownBy(() -> service.parseResetToken(accessToken))
				.isInstanceOfSatisfying(ApiException.class, ex -> assertThat(ex.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST));
	}

	@Test
	void resetTokenRoundTripBindsUserAndOtp() {
		JwtTokenService.ResetToken token = service.issueResetToken(7L, 55L, Instant.now().plus(Duration.ofMinutes(5)));

		JwtTokenService.ParsedResetToken parsed = service.parseResetToken(token.value());

		assertThat(parsed.userId()).isEqualTo(7L);
		assertThat(parsed.otpId()).isEqualTo(55L);
	}

	@Test
	void resetTokenIsRejectedAfterItsExpiry() {
		// Issued an hour ago with a one-minute-ago expiry, so the token is genuinely expired but well-formed.
		Clock anHourAgo = Clock.fixed(Instant.now().minus(Duration.ofHours(1)), ZoneOffset.UTC);
		String expired = TestSupport.jwtTokenService(anHourAgo)
				.issueResetToken(7L, 55L, Instant.now().minus(Duration.ofMinutes(1))).value();

		assertThatThrownBy(() -> service.parseResetToken(expired))
				.isInstanceOfSatisfying(ApiException.class, ex -> assertThat(ex.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST));
	}

	@Test
	void secretShorterThan256BitsIsRejectedWithoutEchoingIt() {
		assertThatThrownBy(() -> JwtConfig.buildSecretKey("short-secret"))
				.isInstanceOf(IllegalStateException.class)
				.hasMessageNotContaining("short-secret");
	}

	@Test
	void missingSecretIsRejected() {
		assertThatThrownBy(() -> JwtConfig.buildSecretKey(null)).isInstanceOf(IllegalStateException.class);
	}

	private static JwtClaimsSet claims(String issuer, String subject, String role, Map<String, Object> extra) {
		Instant now = Instant.now();
		JwtClaimsSet.Builder builder = JwtClaimsSet.builder()
				.issuer(issuer)
				.subject(subject)
				.issuedAt(now)
				.expiresAt(now.plus(Duration.ofMinutes(30)))
				.claim("email", "test@gmail.com")
				.claim("role", role);
		if (extra != null) {
			extra.forEach(builder::claim);
		}
		return builder.build();
	}

}

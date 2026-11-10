package com.gym.auth.support;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.gym.auth.config.JwtConfig;
import com.gym.auth.config.JwtProperties;
import com.gym.auth.exception.ApiException;
import com.gym.auth.security.JwtTokenService;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import javax.crypto.SecretKey;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/**
 * Shared test helpers. The JWT secret is generated at random for each test run, so no secret is
 * hardcoded anywhere in the repository.
 */
public final class TestSupport {

	public static final String ISSUER = "gym-auth-service";
	public static final String JWT_SECRET = randomSecret();
	public static final long ACCESS_TOKEN_MS = 1_800_000L;

	private TestSupport() {
	}

	private static String randomSecret() {
		byte[] bytes = new byte[48];
		new SecureRandom().nextBytes(bytes);
		return Base64.getEncoder().encodeToString(bytes);
	}

	public static SecretKey key() {
		return JwtConfig.buildSecretKey(JWT_SECRET);
	}

	public static JwtTokenService jwtTokenService(Clock clock) {
		SecretKey key = key();
		return new JwtTokenService(JwtConfig.buildEncoder(key), key,
				new JwtProperties(ISSUER, JWT_SECRET, ACCESS_TOKEN_MS), clock);
	}

	public static JwtDecoder accessDecoder() {
		return JwtConfig.buildAccessTokenDecoder(key(), ISSUER);
	}

	/** Signs arbitrary claims with HS256, used to build malformed, foreign-signed or hand-made tokens. */
	public static String sign(SecretKey key, JwtClaimsSet claims) {
		return new NimbusJwtEncoder(new ImmutableSecret<>(key))
				.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims))
				.getTokenValue();
	}

	public static void assertStatus(ThrowingCallable call, HttpStatus status) {
		assertThatThrownBy(call).isInstanceOfSatisfying(ApiException.class,
				ex -> assertThat(ex.getStatus()).isEqualTo(status));
	}

}

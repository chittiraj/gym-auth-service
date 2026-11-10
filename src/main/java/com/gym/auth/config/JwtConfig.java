package com.gym.auth.config;

import com.gym.auth.security.GymJwtValidators;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import com.nimbusds.jose.jwk.source.ImmutableSecret;

@Configuration
public class JwtConfig {

	/** HS256 requires a key of at least 256 bits. */
	public static final int MIN_SECRET_BYTES = 32;

	@Bean
	public SecretKey jwtSecretKey(JwtProperties properties) {
		return buildSecretKey(properties.secret());
	}

	@Bean
	public JwtEncoder jwtEncoder(SecretKey jwtSecretKey) {
		return buildEncoder(jwtSecretKey);
	}

	/** Decoder used by the OAuth2 resource server for protected endpoints such as change-password. */
	@Bean
	@Primary
	public JwtDecoder jwtDecoder(SecretKey jwtSecretKey, JwtProperties properties) {
		return buildAccessTokenDecoder(jwtSecretKey, properties.issuer());
	}

	public static SecretKey buildSecretKey(String secret) {
		// The message deliberately never echoes the secret value.
		if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < MIN_SECRET_BYTES) {
			throw new IllegalStateException(
					"JWT_SECRET must be set to a random value of at least " + MIN_SECRET_BYTES + " bytes");
		}
		return new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
	}

	public static JwtEncoder buildEncoder(SecretKey key) {
		return new NimbusJwtEncoder(new ImmutableSecret<>(key));
	}

	public static JwtDecoder buildAccessTokenDecoder(SecretKey key, String issuer) {
		NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
		decoder.setJwtValidator(GymJwtValidators.accessToken(issuer));
		return decoder;
	}

}

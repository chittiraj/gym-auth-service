package com.gym.auth.security;

import com.gym.auth.config.JwtConfig;
import com.gym.auth.config.JwtProperties;
import com.gym.auth.entity.User;
import com.gym.auth.exception.ApiException;
import java.time.Clock;
import java.time.Instant;
import javax.crypto.SecretKey;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Service;

@Service
public class JwtTokenService {

	public static final String CLAIM_EMAIL = "email";
	public static final String CLAIM_ROLE = "role";
	public static final String CLAIM_OTP_ID = "otp_id";

	private static final String INVALID_RESET_AUTHORIZATION = "Invalid or expired password reset authorization.";

	private final JwtEncoder encoder;
	private final JwtDecoder resetTokenDecoder;
	private final JwtProperties properties;
	private final Clock clock;

	public JwtTokenService(JwtEncoder encoder, SecretKey jwtSecretKey, JwtProperties properties, Clock clock) {
		this.encoder = encoder;
		this.properties = properties;
		this.clock = clock;
		NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(jwtSecretKey).macAlgorithm(MacAlgorithm.HS256).build();
		decoder.setJwtValidator(GymJwtValidators.resetToken(properties.issuer()));
		this.resetTokenDecoder = decoder;
	}

	/** Issues a 30-minute (configurable) access token with sub=user_id, email, role, iss, iat and exp. */
	public AccessToken issueAccessToken(User user) {
		Instant now = Instant.now(clock);
		Instant expiresAt = now.plusMillis(properties.expirationMs());
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuer(properties.issuer())
				.subject(String.valueOf(user.getUserId()))
				.issuedAt(now)
				.expiresAt(expiresAt)
				.claim(CLAIM_EMAIL, user.getEmail())
				.claim(CLAIM_ROLE, user.getRole().name())
				.build();
		return new AccessToken(encode(claims), expiresAt, properties.expirationMs() / 1000);
	}

	/**
	 * Issues the reset authorization returned by a successful OTP verification. It expires with the OTP
	 * row and is bound to that row through the otp_id claim.
	 */
	public ResetToken issueResetToken(Long userId, Long otpId, Instant expiresAt) {
		Instant now = Instant.now(clock);
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuer(properties.issuer())
				.subject(String.valueOf(userId))
				.issuedAt(now)
				.expiresAt(expiresAt)
				.claim(GymJwtValidators.TOKEN_USE, GymJwtValidators.RESET_TOKEN_USE)
				.claim(CLAIM_OTP_ID, otpId)
				.build();
		return new ResetToken(encode(claims), expiresAt);
	}

	/** Validates signature, expiry, issuer and token type, then returns the bound user and OTP ids. */
	public ParsedResetToken parseResetToken(String token) {
		Jwt jwt;
		try {
			jwt = resetTokenDecoder.decode(token);
		} catch (JwtException ex) {
			throw new ApiException(HttpStatus.BAD_REQUEST, INVALID_RESET_AUTHORIZATION);
		}
		if (!(jwt.getClaim(CLAIM_OTP_ID) instanceof Number otpId)) {
			throw new ApiException(HttpStatus.BAD_REQUEST, INVALID_RESET_AUTHORIZATION);
		}
		return new ParsedResetToken(Long.valueOf(jwt.getSubject()), otpId.longValue());
	}

	private String encode(JwtClaimsSet claims) {
		JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
		return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
	}

	public record AccessToken(String value, Instant expiresAt, long expiresInSeconds) {
	}

	public record ResetToken(String value, Instant expiresAt) {
	}

	public record ParsedResetToken(Long userId, Long otpId) {
	}

}

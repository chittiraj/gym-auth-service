package com.gym.auth.security;

import java.util.Set;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;

/**
 * Token rules shared by both services. Access tokens and password-reset tokens are signed with the same
 * key, so the claim {@value #TOKEN_USE} separates them: reset tokens carry it and access tokens never do.
 * A reset token therefore cannot be used as a bearer token for any protected endpoint.
 */
public final class GymJwtValidators {

	public static final String TOKEN_USE = "token_use";
	public static final String RESET_TOKEN_USE = "password_reset";
	public static final String ROLE = "role";
	public static final Set<String> ROLES = Set.of("ADMIN", "STAFF", "MEMBER");

	private GymJwtValidators() {
	}

	/** Validator for access tokens: signature/expiry/issuer (Spring defaults), numeric subject, known role, not a reset token. */
	public static OAuth2TokenValidator<Jwt> accessToken(String issuer) {
		return new DelegatingOAuth2TokenValidator<Jwt>(
				JwtValidators.createDefaultWithIssuer(issuer),
				GymJwtValidators::validSubject,
				GymJwtValidators::validRole,
				GymJwtValidators::notResetToken);
	}

	/** Validator for password-reset tokens: issuer/expiry, numeric subject and the reset token-use claim. */
	public static OAuth2TokenValidator<Jwt> resetToken(String issuer) {
		return new DelegatingOAuth2TokenValidator<Jwt>(
				JwtValidators.createDefaultWithIssuer(issuer),
				GymJwtValidators::validSubject,
				GymJwtValidators::isResetToken);
	}

	private static OAuth2TokenValidatorResult validSubject(Jwt jwt) {
		String subject = jwt.getSubject();
		if (subject != null && subject.matches("\\d{1,19}")) {
			return OAuth2TokenValidatorResult.success();
		}
		return failure("Token subject must be a numeric user id");
	}

	private static OAuth2TokenValidatorResult validRole(Jwt jwt) {
		String role = jwt.getClaimAsString(ROLE);
		if (role != null && ROLES.contains(role)) {
			return OAuth2TokenValidatorResult.success();
		}
		return failure("Token role claim is missing or unknown");
	}

	private static OAuth2TokenValidatorResult notResetToken(Jwt jwt) {
		if (jwt.hasClaim(TOKEN_USE)) {
			return failure("Token type is not accepted for this operation");
		}
		return OAuth2TokenValidatorResult.success();
	}

	private static OAuth2TokenValidatorResult isResetToken(Jwt jwt) {
		if (RESET_TOKEN_USE.equals(jwt.getClaimAsString(TOKEN_USE))) {
			return OAuth2TokenValidatorResult.success();
		}
		return failure("Token is not a password reset token");
	}

	private static OAuth2TokenValidatorResult failure(String description) {
		return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", description, null));
	}

}

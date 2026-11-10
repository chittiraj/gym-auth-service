package com.gym.auth.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Checks the shared service key that the Management Service sends on internal calls. The key comes from
 * INTERNAL_SERVICE_KEY. If it is not set, every internal call is refused. The key itself is never logged.
 */
@Component
public class InternalServiceKeyVerifier {

	public static final String HEADER = "X-Internal-Service-Key";

	/** Minimum length for a configured key. Shorter values are rejected at startup. */
	static final int MIN_KEY_LENGTH = 32;

	private static final Logger log = LoggerFactory.getLogger(InternalServiceKeyVerifier.class);

	/** SHA-256 of the configured key, or null when the endpoint is disabled. Comparing digests keeps lengths private. */
	private final byte[] expectedDigest;

	public InternalServiceKeyVerifier(@Value("${app.internal.service-key:}") String configuredKey) {
		if (configuredKey == null || configuredKey.isBlank()) {
			this.expectedDigest = null;
			log.warn("INTERNAL_SERVICE_KEY is not set; internal account creation is disabled.");
		} else {
			if (configuredKey.length() < MIN_KEY_LENGTH) {
				throw new IllegalStateException(
						"INTERNAL_SERVICE_KEY must be at least " + MIN_KEY_LENGTH + " characters");
			}
			this.expectedDigest = sha256(configuredKey);
		}
	}

	/** Constant-time comparison. Returns false when the endpoint is disabled or no key was presented. */
	public boolean matches(String presentedKey) {
		if (expectedDigest == null || presentedKey == null) {
			return false;
		}
		return MessageDigest.isEqual(expectedDigest, sha256(presentedKey));
	}

	private static byte[] sha256(String value) {
		try {
			return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
		} catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("SHA-256 is not available", ex);
		}
	}

}

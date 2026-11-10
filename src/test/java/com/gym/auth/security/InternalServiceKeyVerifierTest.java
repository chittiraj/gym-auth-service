package com.gym.auth.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class InternalServiceKeyVerifierTest {

	private static final String KEY = "internal-test-key-that-is-long-enough-for-the-check-0123456789";

	@Test
	void matchingKeyIsAccepted() {
		assertThat(new InternalServiceKeyVerifier(KEY).matches(KEY)).isTrue();
	}

	@Test
	void differentKeyOfSameOrDifferentLengthIsRejected() {
		InternalServiceKeyVerifier verifier = new InternalServiceKeyVerifier(KEY);

		assertThat(verifier.matches(KEY + "x")).isFalse();
		assertThat(verifier.matches(KEY.substring(1))).isFalse();
		assertThat(verifier.matches(KEY.replace('i', 'j'))).isFalse();
	}

	@Test
	void missingPresentedKeyIsRejected() {
		assertThat(new InternalServiceKeyVerifier(KEY).matches(null)).isFalse();
	}

	@Test
	void unconfiguredKeyDisablesEveryCall() {
		InternalServiceKeyVerifier blank = new InternalServiceKeyVerifier("");
		InternalServiceKeyVerifier unset = new InternalServiceKeyVerifier(null);

		assertThat(blank.matches("")).isFalse();
		assertThat(blank.matches(KEY)).isFalse();
		assertThat(unset.matches(KEY)).isFalse();
	}

	@Test
	void shortConfiguredKeyFailsAtStartup() {
		assertThatThrownBy(() -> new InternalServiceKeyVerifier("too-short"))
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("at least 32 characters")
				.hasMessageNotContaining("too-short");
	}

}

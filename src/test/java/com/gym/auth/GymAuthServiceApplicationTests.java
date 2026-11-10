package com.gym.auth;

import com.gym.auth.repository.PasswordResetOtpRepository;
import com.gym.auth.repository.UserRepository;
import com.gym.auth.support.TestSupport;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * Verifies that the whole application context wires together. The database is excluded, so this runs
 * without MySQL: repositories and the transaction manager are replaced by mocks.
 */
@SpringBootTest(properties = {
		"spring.autoconfigure.exclude="
				+ "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,"
				+ "org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration,"
				+ "org.springframework.boot.data.jpa.autoconfigure.DataJpaRepositoriesAutoConfiguration"
})
class GymAuthServiceApplicationTests {

	@MockitoBean
	UserRepository userRepository;

	@MockitoBean
	PasswordResetOtpRepository passwordResetOtpRepository;

	@MockitoBean
	PlatformTransactionManager transactionManager;

	@DynamicPropertySource
	static void jwtSecret(DynamicPropertyRegistry registry) {
		registry.add("app.jwt.secret", () -> TestSupport.JWT_SECRET);
	}

	@Test
	void contextLoads() {
	}

}

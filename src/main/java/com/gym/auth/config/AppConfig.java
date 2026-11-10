package com.gym.auth.config;

import java.time.Clock;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;

@Configuration
@EnableAsync
@EnableConfigurationProperties({JwtProperties.class, PasswordResetProperties.class})
public class AppConfig {

	/** Single time source for the application, so time-dependent logic can be tested deterministically. */
	@Bean
	public Clock clock() {
		return Clock.systemDefaultZone();
	}

}

package com.gym.auth.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.nio.charset.StandardCharsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * Sends OTP emails through Gmail SMTP. Runs asynchronously. Failures are logged without the OTP, the
 * recipient address or the SMTP credentials, and the caller never learns the outcome.
 */
@Service
public class PasswordResetEmailService {

	private static final Logger log = LoggerFactory.getLogger(PasswordResetEmailService.class);

	private final JavaMailSender mailSender;
	private final String fromAddress;

	public PasswordResetEmailService(JavaMailSender mailSender,
			@Value("${spring.mail.username:}") String fromAddress) {
		this.mailSender = mailSender;
		this.fromAddress = fromAddress;
	}

	@Async
	public void sendPasswordResetOtp(Long userId, String recipient, String fullName, String otp,
			long expiryMinutes) {
		try {
			MimeMessage message = mailSender.createMimeMessage();
			MimeMessageHelper helper = new MimeMessageHelper(message, true, StandardCharsets.UTF_8.name());
			helper.setFrom(fromAddress);
			helper.setTo(recipient);
			helper.setSubject("GYM Management - Your password reset code");
			helper.setText(
					OtpEmailTemplate.plainText(fullName, otp, expiryMinutes),
					OtpEmailTemplate.html(fullName, otp, expiryMinutes));
			mailSender.send(message);
			log.info("Password reset OTP email sent for user id {}", userId);
		} catch (MessagingException | MailException ex) {
			log.error("Password reset OTP email could not be sent for user id {} ({})",
					userId, ex.getClass().getSimpleName());
		}
	}

}

package com.gym.auth.service;

import org.springframework.web.util.HtmlUtils;

/** Plain-text and HTML bodies for the password reset OTP email. */
final class OtpEmailTemplate {

	private OtpEmailTemplate() {
	}

	static String plainText(String fullName, String otp, long expiryMinutes) {
		return """
				Hello %s,

				We received a request to reset the password for your GYM Management account.

				Your verification code is: %s

				This code expires in %d minutes and can be used only once.

				Security notice: if you did not request a password reset, ignore this email. \
				Your password will not change unless the code is entered on the reset page. \
				Never share this code with anyone, including gym staff.

				- GYM Management
				"""
				.formatted(plainName(fullName), otp, expiryMinutes);
	}

	static String html(String fullName, String otp, long expiryMinutes) {
		String name = HtmlUtils.htmlEscape(plainName(fullName));
		return """
				<!doctype html>
				<html>
				<body style="margin:0;padding:0;background:#f4f6f8;font-family:Arial,Helvetica,sans-serif;color:#1f2933;">
				  <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="padding:24px 12px;">
				    <tr><td align="center">
				      <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="max-width:520px;background:#ffffff;border-radius:8px;padding:28px;">
				        <tr><td style="font-size:20px;font-weight:bold;color:#0b5cad;">GYM Management</td></tr>
				        <tr><td style="padding-top:18px;font-size:15px;line-height:22px;">
				          Hello %s,<br><br>
				          We received a request to reset the password for your account. Use the verification code below to continue.
				        </td></tr>
				        <tr><td align="center" style="padding:24px 0;">
				          <span style="display:inline-block;font-size:30px;letter-spacing:8px;font-weight:bold;background:#eef4fb;border-radius:6px;padding:14px 22px;">%s</span>
				        </td></tr>
				        <tr><td style="font-size:14px;line-height:20px;">
				          This code expires in <strong>%d minutes</strong> and can be used only once.
				        </td></tr>
				        <tr><td style="padding-top:20px;font-size:13px;line-height:19px;color:#7b8794;border-top:1px solid #e4e7eb;">
				          <strong>Security notice:</strong> if you did not request a password reset, you can ignore this email. Never share this code with anyone, including gym staff.
				        </td></tr>
				      </table>
				    </td></tr>
				  </table>
				</body>
				</html>
				""".formatted(name, otp, expiryMinutes);
	}

	private static String plainName(String fullName) {
		return fullName == null || fullName.isBlank() ? "member" : fullName.trim();
	}

}

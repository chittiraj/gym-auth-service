package com.gym.auth.exception;

import com.gym.auth.dto.ApiErrorResponse;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Converts exceptions into a uniform error body. Responses never echo request payloads, tokens,
 * passwords or OTPs, and unexpected failures return a generic message.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

	private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

	@ExceptionHandler(ApiException.class)
	public ResponseEntity<ApiErrorResponse> handleApiException(ApiException ex) {
		return build(ex.getStatus(), ex.getMessage(), null);
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<ApiErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
		Map<String, String> fieldErrors = new LinkedHashMap<>();
		ex.getBindingResult().getFieldErrors()
				.forEach(error -> fieldErrors.putIfAbsent(error.getField(), error.getDefaultMessage()));
		return build(HttpStatus.BAD_REQUEST, "Validation failed", fieldErrors);
	}

	@ExceptionHandler(HttpMessageNotReadableException.class)
	public ResponseEntity<ApiErrorResponse> handleUnreadableBody(HttpMessageNotReadableException ex) {
		return build(HttpStatus.BAD_REQUEST, "Malformed request body", null);
	}

	@ExceptionHandler(DataIntegrityViolationException.class)
	public ResponseEntity<ApiErrorResponse> handleDataIntegrity(DataIntegrityViolationException ex) {
		log.warn("Data integrity violation: {}", ex.getClass().getSimpleName());
		return build(HttpStatus.CONFLICT, "The request conflicts with existing data", null);
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<ApiErrorResponse> handleUnexpected(Exception ex) {
		if (ex instanceof ErrorResponse errorResponse) {
			HttpStatus status = HttpStatus.resolve(errorResponse.getStatusCode().value());
			if (status != null) {
				return build(status, status.getReasonPhrase(), null);
			}
		}
		log.error("Unexpected error while processing request", ex);
		return build(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred", null);
	}

	private ResponseEntity<ApiErrorResponse> build(HttpStatus status, String message,
			Map<String, String> fieldErrors) {
		ApiErrorResponse body = new ApiErrorResponse(Instant.now(), status.value(), status.getReasonPhrase(),
				message, fieldErrors);
		return ResponseEntity.status(status).body(body);
	}

}

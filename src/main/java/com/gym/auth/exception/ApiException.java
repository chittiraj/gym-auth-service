package com.gym.auth.exception;

import org.springframework.http.HttpStatus;

/** Expected, client-facing failure. The message is safe to return to the caller. */
public class ApiException extends RuntimeException {

	private final HttpStatus status;

	public ApiException(HttpStatus status, String message) {
		super(message);
		this.status = status;
	}

	public HttpStatus getStatus() {
		return status;
	}

}

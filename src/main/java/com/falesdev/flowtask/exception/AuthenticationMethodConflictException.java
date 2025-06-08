package com.falesdev.flowtask.exception;

public class AuthenticationMethodConflictException extends RuntimeException {
    public AuthenticationMethodConflictException(String message) {
        super(message);
    }
}

package com.falesdev.flowtask.service;

public interface EmailService {
    void sendWelcomeEmail(String to, String name);
    void sendOtpEmail(String to, String otp);
    void sendPasswordChangedNotification(String to, String name);
}

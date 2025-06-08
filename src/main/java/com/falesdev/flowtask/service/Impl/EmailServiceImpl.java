package com.falesdev.flowtask.service.Impl;

import com.falesdev.flowtask.exception.EmailSendingException;
import com.falesdev.flowtask.service.EmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    @Value("${spring.mail.username}")
    private String email;

    private final JavaMailSender mailSender;
    private final SpringTemplateEngine templateEngine;
    private final ClassPathResource logo = new ClassPathResource("static/logo.png");

    @Async
    @Override
    public void sendWelcomeEmail(String to, String name) {
        try {
            Context context = new Context();
            context.setVariable("name", name);
            sendEmail(to, "¡Bienvenido a Flowtask!", "welcome-email", context);
        } catch (MessagingException e) {
            throw new EmailSendingException("Error sending OTP email", e);
        }
    }

    @Async
    @Override
    public void sendOtpEmail(String to, String otp) {
        try {
            Context context = new Context();
            context.setVariable("otp", otp);
            sendEmail(to, "Tu código de acceso", "otp-email", context);
        } catch (MessagingException e) {
            throw new EmailSendingException("Error sending OTP email", e);
        }
    }

    private void sendEmail(String to, String subject, String templateName, Context context) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setFrom(email);
        helper.setTo(to);
        helper.setSubject(subject);

        context.setVariable("imageResourceName", "logo.png");
        String html = templateEngine.process(templateName, context);
        helper.setText(html, true);

        helper.addInline("logo", logo);
        mailSender.send(message);
    }

    @Async
    @Override
    public void sendPasswordChangedNotification(String to, String name) {
        try {
            Context context = new Context();
            context.setVariable("name", name);
            sendEmail(to, "Tu contraseña ha sido actualizada", "password-changed-email", context);
        } catch (MessagingException e) {
            throw new EmailSendingException("Error sending password changed notification", e);
        }
    }
}

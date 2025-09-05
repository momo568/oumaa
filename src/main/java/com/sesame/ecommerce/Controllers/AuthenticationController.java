package com.sesame.ecommerce.Controllers;

import com.sesame.ecommerce.Exception.OTPExpiredException;
import com.sesame.ecommerce.Models.DTO.request.*;
import com.sesame.ecommerce.Models.DTO.request.response.JwtAuthenticationResponse;
import com.sesame.ecommerce.Models.User;
import com.sesame.ecommerce.Repositories.UserRepository;
import com.sesame.ecommerce.Security.AuthenticationService;
import com.sesame.ecommerce.Security.EmailVerificationService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final EmailVerificationService emailVerificationService;
    private final UserRepository userRepository;

    @Value("${app.verification-url:http://localhost:8087/api/v1/auth/verify}")
    private String verificationUrl;

    @Value("${app.frontend-url:http://localhost:4200/pages/login}")
    private String frontendUrl;

    @PostMapping("/signup")
    public ResponseEntity<JwtAuthenticationResponse> signup(@RequestBody SignUpRequest request) {
        return ResponseEntity.ok(authenticationService.SignUp(request));
    }

    @GetMapping("/verify")
    public void verifyAccount(
            @RequestParam String token,
            HttpServletResponse response) throws IOException {

        try {
            User user = userRepository.findByVerificationToken(token)
                    .orElseThrow(() -> new RuntimeException("Invalid verification token"));

            if (user.getVerificationTokenExpiry().isBefore(LocalDateTime.now())) {
                throw new RuntimeException("Verification link has expired");
            }

            user.setVerified(true);
            user.setVerificationToken(null);
            user.setVerificationTokenExpiry(null);
            userRepository.save(user);

            String redirectUrl = frontendUrl +
                    "?verified=true" +
                    "&email=" + URLEncoder.encode(user.getEmail(), StandardCharsets.UTF_8) +
                    "&message=" + URLEncoder.encode("Account verified successfully!", StandardCharsets.UTF_8);

            response.sendRedirect(redirectUrl);

        } catch (RuntimeException e) {
            // Redirect to frontend LOGIN page with error status
            String redirectUrl = frontendUrl +
                    "?verified=false" +
                    "&error=" + URLEncoder.encode(e.getMessage(), StandardCharsets.UTF_8);

            response.sendRedirect(redirectUrl);
        }
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<?> resendVerificationEmail(@RequestParam String email) {
        try {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found with email: " + email));

            if (user.isVerified()) {
                return ResponseEntity.badRequest().body("Account is already verified");
            }

            // Generate new token and expiry
            String newToken = UUID.randomUUID().toString();
            user.setVerificationToken(newToken);
            user.setVerificationTokenExpiry(LocalDateTime.now().plusDays(1));
            userRepository.save(user);

            // Send new verification email
            emailVerificationService.sendVerificationEmail(user);

            return ResponseEntity.ok().body("Verification email sent successfully");

        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred while sending verification email");
        }
    }

    @PostMapping("/signin")
    public ResponseEntity<JwtAuthenticationResponse> signin(
            @RequestBody SigninRequest request,
            HttpServletResponse response
    ) {
        JwtAuthenticationResponse jwtResponse = authenticationService.SignIn(request);

        response.setHeader("Access-Control-Expose-Headers", "Authorization");
        response.setHeader("Authorization", "Bearer " + jwtResponse.getAccessToken());

        return ResponseEntity.ok(jwtResponse);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<JwtAuthenticationResponse> refreshToken(
            @RequestBody RefreshTokenRequest request,
            HttpServletResponse httpResponse
    ) {
        JwtAuthenticationResponse response = authenticationService.refreshToken(request);

        httpResponse.setHeader("Access-Control-Expose-Headers", "Authorization");
        httpResponse.setHeader("Authorization", "Bearer " + response.getAccessToken());

        return ResponseEntity.ok(response);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        try {
            authenticationService.sendForgotPasswordEmail(request.getEmail());
            return ResponseEntity.ok().body("Password reset email sent successfully");
        } catch (OTPExpiredException ex) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred");
        }
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOTP(@RequestParam String email, @RequestParam String otp) {
        try {
            authenticationService.verifyOTP(email, otp);
            return ResponseEntity.ok().body("OTP verified successfully");
        } catch (OTPExpiredException ex) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("OTP verification failed: " + ex.getMessage());
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred");
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest request) {
        try {
            authenticationService.resetPassword(request);
            return ResponseEntity.ok().body("Password reset successfully");
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred");
        }
    }
}
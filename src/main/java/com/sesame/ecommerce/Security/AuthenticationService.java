package com.sesame.ecommerce.Security;

import com.sesame.ecommerce.Models.DTO.request.*;
import com.sesame.ecommerce.Models.DTO.request.response.JwtAuthenticationResponse;

public interface AuthenticationService {
    JwtAuthenticationResponse SignUp(SignUpRequest request);
    JwtAuthenticationResponse SignIn(SigninRequest request);
    JwtAuthenticationResponse refreshToken(RefreshTokenRequest request);
    void sendForgotPasswordEmail(String email);
    void verifyOTP(String email, String otp);
    void resetPassword(ResetPasswordRequest request);
}

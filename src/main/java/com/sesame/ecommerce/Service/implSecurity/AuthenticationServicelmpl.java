package com.sesame.ecommerce.Service.implSecurity;

import com.sesame.ecommerce.Exception.TokenRefreshException;
import com.sesame.ecommerce.Models.DTO.request.RefreshTokenRequest;
import com.sesame.ecommerce.Models.DTO.request.SignUpRequest;
import com.sesame.ecommerce.Models.DTO.request.SigninRequest;
import com.sesame.ecommerce.Models.DTO.request.response.JwtAuthenticationResponse;
import com.sesame.ecommerce.Models.RefreshToken;
import com.sesame.ecommerce.Models.Role;
import com.sesame.ecommerce.Models.User;
import com.sesame.ecommerce.Repositories.UserRepository;
import com.sesame.ecommerce.Security.AuthenticationService;
import com.sesame.ecommerce.Security.JwtService;
import com.sesame.ecommerce.Security.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationServicelmpl implements AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    @Override
    public JwtAuthenticationResponse SignUp(SignUpRequest request) {
        Role role = request.getRole() != null ? request.getRole() : Role.CUSTOMER;
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(role)
                .build();
        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);

        var refreshToken = refreshTokenService.createRefreshToken(user.getId());

        return JwtAuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken.getToken())
                .userId(user.getId())
                .role(user.getRole().name())
                .tokenType("Bearer")
                .build();
    }

    @Override
    public JwtAuthenticationResponse SignIn(SigninRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));

        var jwtToken = jwtService.generateToken(user);
        var refreshToken = refreshTokenService.createRefreshToken(user.getId());

        return JwtAuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken.getToken())
                .userId(user.getId())
                .role(user.getRole().name())
                .tokenType("Bearer")
                .build();
    }

    @Override
    public JwtAuthenticationResponse refreshToken(RefreshTokenRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = jwtService.generateToken(user);
                    return JwtAuthenticationResponse.builder()
                            .accessToken(token)
                            .refreshToken(requestRefreshToken)
                            .userId(user.getId())
                            .role(user.getRole().name())
                            .tokenType("Bearer")
                            .build();
                })
                .orElseThrow(() -> new TokenRefreshException(
                        requestRefreshToken,
                        "Refresh token is not in database!"
                ));
    }
}
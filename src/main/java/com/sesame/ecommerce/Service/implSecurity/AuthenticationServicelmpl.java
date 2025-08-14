package com.sesame.ecommerce.Service.implSecurity;

import com.sesame.ecommerce.Models.DTO.request.SignUpRequest;
import com.sesame.ecommerce.Models.DTO.request.SigninRequest;
import com.sesame.ecommerce.Models.DTO.request.response.JwtAuthenticationResponse;
import com.sesame.ecommerce.Models.Role;
import com.sesame.ecommerce.Models.User;
import com.sesame.ecommerce.Repositories.UserRepository;
import com.sesame.ecommerce.Security.AuthenticationService;
import com.sesame.ecommerce.Security.JwtService;
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
        return JwtAuthenticationResponse.builder()
                .accessToken(jwtToken)
                .userId(user.getId())
                .role(user.getRole().name())
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
        var refreshToken = jwtService.generateRefreshToken(user);

        return JwtAuthenticationResponse.builder()
                .accessToken(jwtToken)
                .userId(user.getId())
                .role(user.getRole().name())
                .build();
    }
}

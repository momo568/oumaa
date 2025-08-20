package com.sesame.ecommerce.Controllers;

import com.sesame.ecommerce.Models.DTO.request.RefreshTokenRequest;
import com.sesame.ecommerce.Models.DTO.request.SignUpRequest;
import com.sesame.ecommerce.Models.DTO.request.SigninRequest;
import com.sesame.ecommerce.Models.DTO.request.response.JwtAuthenticationResponse;
import com.sesame.ecommerce.Security.AuthenticationService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/signup")
    public ResponseEntity<JwtAuthenticationResponse> signup(@RequestBody SignUpRequest request) {
        return ResponseEntity.ok(authenticationService.SignUp(request));
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

}

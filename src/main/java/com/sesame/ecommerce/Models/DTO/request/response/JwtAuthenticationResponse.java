package com.sesame.ecommerce.Models.DTO.request.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtAuthenticationResponse {
    private String accessToken;
    private Long userId;
    private String role;
    private String refreshToken;
    private  String  tokenType;
    private Boolean isVerified;
    public String getAccessToken() {
        return this.accessToken;
    }
}

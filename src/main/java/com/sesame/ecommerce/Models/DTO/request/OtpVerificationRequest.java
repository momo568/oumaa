package com.sesame.ecommerce.Models.DTO.request;

import lombok.Data;

@Data
public class OtpVerificationRequest {
    private String email;
    private String otp;
}

package com.sesame.ecommerce.Service.implSecurity;

import com.sesame.ecommerce.Exception.TokenRefreshException;
import com.sesame.ecommerce.Models.RefreshToken;
import com.sesame.ecommerce.Models.User;
import com.sesame.ecommerce.Repositories.RefreshTokenRepository;
import com.sesame.ecommerce.Repositories.UserRepository;
import com.sesame.ecommerce.Security.JwtService;
import com.sesame.ecommerce.Security.RefreshTokenService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RefreshTokenServicelmpl implements RefreshTokenService {

    @Value("${jwt.refresh.expiration.ms}")
    private Long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    @Override
    public RefreshToken createRefreshToken(Long userId) {
        // Récupérer l'utilisateur par ID
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));

        // Vérifier s'il existe déjà un refresh token pour cet utilisateur
        Optional<RefreshToken> existingToken = refreshTokenRepository.findByUser(user);

        // Générer un nouveau token JWT
        String token = jwtService.generateRefreshToken(user);
        if (token.length() > 512) {
            throw new IllegalStateException("Generated token exceeds maximum length");
        }

        // Mettre à jour le token existant s'il est présent
        if (existingToken.isPresent()) {
            RefreshToken refreshToken = existingToken.get();
            refreshToken.setToken(token);
            refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
            return refreshTokenRepository.save(refreshToken);
        }

        // Créer un nouveau refresh token
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(token)
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    @Override
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(
                    token.getToken(),
                    "Refresh token was expired. Please make a new sign-in request."
            );
        }
        return token;
    }

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Override
    @Transactional
    public void deleteByUserId(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));

        refreshTokenRepository.deleteByUser(user);
    }
}

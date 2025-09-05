package com.sesame.ecommerce.Models;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(
        name = "users",
        uniqueConstraints = {@UniqueConstraint(name = "email", columnNames = "email")}
)
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Getter
    @Setter
    @Column
    private String firstName;
    @Getter
    @Setter
    @Column
    private String lastName;
    @Column(name = "fullname")
    private String fullName;

    @Column(name = "email", unique = true)
    private String email;

    private String password;
    @Column
    private String otp;

    @Column
    private LocalDateTime otpExpiry;
    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private Role role;
@Column(name ="is_verified",nullable = false)
private boolean isVerified = false ;
@Column(name = "verification_token")
private String verificationToken;
@Column(name = "verification_token_expiry")
private LocalDateTime verificationTokenExpiry;
@Column(name = "is_enabled",nullable = false)
private Boolean isEnabled =true;
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority( role.name()));
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}




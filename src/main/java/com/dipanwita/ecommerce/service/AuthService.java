package com.dipanwita.ecommerce.service;

import com.dipanwita.ecommerce.config.JwtUtil;
import com.dipanwita.ecommerce.dto.AuthResponse;
import com.dipanwita.ecommerce.dto.LoginRequest;
import com.dipanwita.ecommerce.dto.RegisterRequest;
import com.dipanwita.ecommerce.model.Role;
import com.dipanwita.ecommerce.model.User;
import com.dipanwita.ecommerce.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthResponse register(RegisterRequest request){
        //check if email already exists
        if(userRepository.existsByEmail(request.getEmail())){
            throw new RuntimeException("Email already registered!");
        }

        //Build user
        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(request.getRole() != null
                ? Role.valueOf(request.getRole().toUpperCase())
                : Role.USER);

        userRepository.save(user);

        //Generate token
        String token = jwtUtil.generateToken(user.getEmail(), user.getRole().name());

        return new AuthResponse(token, user.getRole().name(), "Register successful!");
    }

    public AuthResponse login(LoginRequest request){
        // Find user by email
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Invalid email or password!"));

        // Check password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid email or password!");
        }

        // Generate token
        String token = jwtUtil.generateToken(user.getEmail(), user.getRole().name());

        return new AuthResponse(token, user.getRole().name(), "Login successful!");
    }
}

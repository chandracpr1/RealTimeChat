package com.authservice.Service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.authservice.DTOs.SignupRequest;
import com.authservice.Entity.User;
import com.authservice.Repository.UserRepository;

import jakarta.el.ELException;
import jakarta.transaction.Transactional;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder)
    {
        this.userRepository=userRepository;
        this.passwordEncoder=passwordEncoder;
    }
    
    @Transactional
    public User registerUser(SignupRequest req)
    {
        if(userRepository.existsByUsername(req.getUsername()))
            throw new IllegalArgumentException("Username Already Taken");
        if(userRepository.existsByEmail(req.getEmail()))
            throw new IllegalArgumentException("Email Already Registered");
        User user=new User();
        user.setEmail(req.getEmail());
        user.setUsername(req.getUsername());
        user.setPassword(passwordEncoder.encode(req.getPassword()));
        return userRepository.save(user);
    }
}

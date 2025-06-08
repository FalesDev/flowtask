package com.falesdev.flowtask.security.service;

import com.falesdev.flowtask.domain.entity.User;
import com.falesdev.flowtask.repository.postgres.UserRepository;
import com.falesdev.flowtask.security.FlowUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@RequiredArgsConstructor
public class FlowUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not fount with email: " + email));
        return new FlowUserDetails(user);
    }
}

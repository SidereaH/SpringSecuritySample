package com.wndtback.controllers;

import com.wndtback.dto.UserDTO;
import com.wndtback.models.UserDetailsImpl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
@CrossOrigin("http://localhost:3000")
@RestController
@RequestMapping("/secured")
public class MainController {
    @GetMapping("/username")
    public String userAccess(Principal principal) {
        if (principal != null) {
            return principal.getName();
        }
        return null;
    }
    @GetMapping("/user")
    public UserDTO userAccess(Authentication authentication) {
        if (authentication != null) {
            Object principal = authentication.getPrincipal();

            if (principal instanceof UserDetails) {
                UserDetails userDetails = (UserDetails) principal;

                String role = userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .findFirst()
                        .orElse("ROLE_UNKNOWN");
                var userDto = new UserDTO(userDetails.getUsername(),
                        ((UserDetailsImpl) userDetails).getEmail(),
                        role);
                return new ResponseEntity<>(userDto, HttpStatus.OK).getBody();

            }
        }
        return null;
    }
}

package com.wndtback.models;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
@Table(name = "user_d")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column
    private String username;
    @Column
    private String email;
    @Column
    private String password;
    @Column
    private String role;
}

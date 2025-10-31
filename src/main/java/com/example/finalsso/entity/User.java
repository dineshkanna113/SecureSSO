package com.example.finalsso.entity;

import javax.persistence.*;
import lombok.Data;

@Entity
@Data
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @javax.persistence.Column(unique = true)
    private String username;
    private String password;
    private String email;

    private String firstName;
    private String lastName;

    @Column(nullable = false)
    private String role = "ROLE_USER"; // ROLE_USER or ROLE_ADMIN

    @Column(nullable = false)
    private boolean enabled = true;
}

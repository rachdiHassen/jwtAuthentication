package com.example.jwtauthentication.security.entities;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
@Entity
@Data @NoArgsConstructor @AllArgsConstructor
public class AppRole {
    @Id
    private String roleName;

}

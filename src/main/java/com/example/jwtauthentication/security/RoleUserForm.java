package com.example.jwtauthentication.security;


import lombok.Data;


@Data
public class RoleUserForm {
    private String userName;
    private String roleName;
}

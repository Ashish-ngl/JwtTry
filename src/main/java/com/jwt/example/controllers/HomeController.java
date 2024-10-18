package com.jwt.example.controllers;


import com.jwt.example.entities.User;
import com.jwt.example.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.sql.SQLOutput;
import java.util.List;

@RestController
@RequestMapping("/home")
public class HomeController {

    @Autowired
    private UserService userService;
    @GetMapping("/users")
    public List<User> getUsers(){
        System.out.println("getting user");


        return userService.getUsers();
    }

    @GetMapping("/current")
    public String getCurrentUser(Principal principal){
        return principal.getName();
    }
}

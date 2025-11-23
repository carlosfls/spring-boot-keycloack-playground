package org.carlosacademic.keycloackplayground.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello/admin")
    public ResponseEntity<String> helloAdmin() {
        return ResponseEntity.ok("Hello World - ADMIN!");
    }

    @GetMapping("/hello/user")
    public ResponseEntity<String> helloUser() {
        return ResponseEntity.ok("Hello World - USER!");
    }
}

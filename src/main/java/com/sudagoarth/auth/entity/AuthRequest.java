package com.sudagoarth.auth.entity;

public record AuthRequest(String username, String password) {

    @Override
    public String toString() {
        return String.format("AuthRequest{username='%s', password='%s'}", username, password);
    }

}
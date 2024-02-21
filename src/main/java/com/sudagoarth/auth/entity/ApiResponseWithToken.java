package com.sudagoarth.auth.entity;

public  record  ApiResponseWithToken(boolean success, String message, Object data, String token) {

}
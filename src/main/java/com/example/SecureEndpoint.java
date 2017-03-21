package com.example;


import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecureEndpoint {
    @RequestMapping(
            value = "/secret",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseBody
    public String secret() {
        return "{ \"secret\" : \"This is secret. Don't tell anyone\" }";
    }

    @RequestMapping(
            value = "/top/secret",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseBody
    public String topSecret() {
        return "{ \"topSecret\" : \"This is really top secret. Don't tell anyone or we will kill you.\" }";
    }
}

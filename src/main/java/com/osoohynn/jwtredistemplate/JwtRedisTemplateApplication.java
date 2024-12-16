package com.osoohynn.jwtredistemplate;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class JwtRedisTemplateApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtRedisTemplateApplication.class, args);
    }

}

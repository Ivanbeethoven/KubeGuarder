package com.nanxing.kubeguard;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class KubeGuardApplication {

    public static void main(String[] args) {
        SpringApplication.run(KubeGuardApplication.class, args);
    }

}

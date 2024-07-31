package com.nanxing.webhookadmissioncontroller.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

/**
 * Author: Nanxing
 * Date: 2024/3/15 15:36
 */
@Configuration
public class WebhookConfig {
    @Bean
    public RestTemplate setRestTemplate(){
        return new RestTemplate();
    }
}

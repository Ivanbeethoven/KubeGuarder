package com.nanxing.kubeguard.configuration;

import com.nanxing.kubeguard.client.KubernetesClient;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.util.Config;
import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Author: Nanxing
 * Date: 2024/3/5 16:53
 */
@Configuration
//@Data
//@ConfigurationProperties(prefix = "kubernetes")
public class KubernetesClientConfig {
    @Value("${kubernetes.url}")
    private String url;

    @Value("${kubernetes.token}")
    private String token;

    @Bean
    public KubernetesClient setKubernetesClient(){
        ApiClient client = Config.fromToken(url, token, false);
        io.kubernetes.client.openapi.Configuration.setDefaultApiClient(client);
        return new KubernetesClient(client);
    }

}

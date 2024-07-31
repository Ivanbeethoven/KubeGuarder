package com.nanxing.kubeguard.entity.auth;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Author: Nanxing
 * Date: 2024/3/5 10:50
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Resource {
    private String kind;
    private String apiVersion;
    private String namespace;
    private String name;
}

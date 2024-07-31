package com.nanxing.kubeguard.entity.auth;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * Author: Nanxing
 * Date: 2024/3/6 11:28
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Pod {
    private String name;
    private String namespace;
    private String serviceAccountName;
    private String ip;
    private Map<String, String> labels;
}

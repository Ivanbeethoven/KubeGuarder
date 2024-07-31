package com.nanxing.kubeguard.entity.webhook;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Author: Nanxing
 * Date: 2024/3/14 20:10
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AR_Resource {
    private String group;
    private String version;
    private String resource;
}

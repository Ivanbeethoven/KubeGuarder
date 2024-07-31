package com.nanxing.kubeguard.entity.audit;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Author: Nanxing
 * Date: 2024/3/5 10:34
 */

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ObjectRef {
    private String resource;
    private String namespace;
    private String name;
    private String apiVersion;
    private String apiGroup;
}

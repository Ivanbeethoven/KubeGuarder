package com.nanxing.kubeguard.entity.auth;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Author: Nanxing
 * Date: 2024/3/13 17:09
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class MetaRule {
    private List<String> apiGroups;
    private String kind;
    private String verb;
    private String resourceName;
}

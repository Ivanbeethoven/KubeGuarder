package com.nanxing.kubeguard.entity.auth;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Author: Nanxing
 * Date: 2024/3/5 11:47
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Rule {
    private List<String> apiGroups;
    private List<String> classes;
    private List<String> verbs;
    private List<String> resourceNames;
    private List<String> nonResourceURLs;
}

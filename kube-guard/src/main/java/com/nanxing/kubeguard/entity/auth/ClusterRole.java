package com.nanxing.kubeguard.entity.auth;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Author: Nanxing
 * Date: 2024/3/5 11:47
 */
@NoArgsConstructor
@AllArgsConstructor
@Data
public class ClusterRole {
    private String name;
    private List<Rule> ruleList;
}

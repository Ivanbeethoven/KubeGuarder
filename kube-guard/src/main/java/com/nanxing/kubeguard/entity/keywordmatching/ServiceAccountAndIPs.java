package com.nanxing.kubeguard.entity.keywordmatching;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


import java.util.List;
import java.util.Set;

/**
 * Author: Nanxing
 * Date: 2024/3/22 15:01
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ServiceAccountAndIPs {
    private String namespace;
    private String name;
    private Set<String> podIPSet;
    private Set<String> clusterServiceIPSet;
    private Set<Integer> nodePortSet;
}

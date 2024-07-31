package com.nanxing.kubeguard.entity.auth;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Author: Nanxing
 * Date: 2024/3/5 10:57
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ServiceAccount {
    private String apiVersion;
    private String namespace;
    private String name;
    private List<Pod> podList;
    private List<Role> roleList;
    private List<ClusterRole> clusterRoleList;
}

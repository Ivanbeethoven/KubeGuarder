package com.nanxing.kubeguard.entity.runtimecheck;

import com.alibaba.fastjson.annotation.JSONField;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Author: Nanxing
 * Date: 2024/3/15 16:14
 */
@AllArgsConstructor
@NoArgsConstructor
@Data
public class PrivilegeEscalationType {

    public static String STEALING_CREDENTIALS = "Stealing credentials";
    public static String IMPERSONATE_ACCOUNTS = "Impersonate accounts";
    public static String OPERATING_RBAC = "Operating RBAC";
    public static String INDIRECT_EXECUTION = "Indirect execution";

    @JSONField(ordinal = 1)
    private String type;

    @JSONField(ordinal = 2)
    private String message;
}

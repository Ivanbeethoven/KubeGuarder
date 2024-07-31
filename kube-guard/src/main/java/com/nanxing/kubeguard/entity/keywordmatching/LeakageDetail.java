package com.nanxing.kubeguard.entity.keywordmatching;

import com.alibaba.fastjson.annotation.JSONField;
import com.nanxing.kubeguard.entity.auth.ServiceAccount;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Author: Nanxing
 * Date: 2024/3/24 10:55
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LeakageDetail {
    @JSONField(ordinal = 1)
    private String serviceAccountNamespace;
    @JSONField(ordinal = 2)
    private String serviceAccountName;
    @JSONField(ordinal = 3)
    private String destIP;
    @JSONField(ordinal = 4)
    private List<ResourceAndKeywords> targetedKeywords;
}

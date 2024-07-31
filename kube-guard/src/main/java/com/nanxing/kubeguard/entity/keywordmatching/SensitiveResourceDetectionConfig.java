package com.nanxing.kubeguard.entity.keywordmatching;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Author: Nanxing
 * Date: 2024/3/17 14:44
 */
@NoArgsConstructor
@AllArgsConstructor
@Data
public class SensitiveResourceDetectionConfig {
    private Integer expireTime;
    private List<ResourceKeywordConfig> items;
}

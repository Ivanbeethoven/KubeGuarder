package com.nanxing.kubeguard.entity.keywordmatching;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.scheduling.annotation.Async;

import java.util.List;

/**
 * Author: Nanxing
 * Date: 2024/3/17 14:47
 */

@NoArgsConstructor
@AllArgsConstructor
@Data
public class ResourceKeywordConfig {
    private String apiGroup;
    private String resource;
    private List<String> fields;
}

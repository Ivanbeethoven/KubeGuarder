package com.nanxing.kubeguard.entity.keywordmatching;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * Author: Nanxing
 * Date: 2024/3/18 16:54
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResourceAndKeywords {
    private String apiGroup;
    private String resource;
    private String namespace;
    private String name;
    private Map<String, String> keywordMap;

    public String getResourceSignature(){
        String ns = this.namespace == null ? "cluster" : this.namespace;
        return resource + "-" + ns + "-" + name;
    }
}

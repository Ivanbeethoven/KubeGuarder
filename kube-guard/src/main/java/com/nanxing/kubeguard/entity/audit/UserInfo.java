package com.nanxing.kubeguard.entity.audit;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * Author: Nanxing
 * Date: 2024/3/5 10:33
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserInfo {
    private String username;
    private String uid;
    private List<String> groups;
    private Map<String, String> extra;
}

package com.nanxing.kubeguard.entity.runtimecheck;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.annotation.JSONField;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Author: Nanxing
 * Date: 2024/3/15 11:39
 */

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DynamicDetectionReport {
    @JSONField(ordinal = 1)
    private boolean isOverPrivilege;

    @JSONField(ordinal = 2)
    private List<PrivilegeEscalationType> typeList;

    @JSONField(ordinal = 3)
    private Operation operation;
}

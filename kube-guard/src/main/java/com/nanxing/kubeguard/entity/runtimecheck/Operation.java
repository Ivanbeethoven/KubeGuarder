package com.nanxing.kubeguard.entity.runtimecheck;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.annotation.JSONField;
import com.nanxing.kubeguard.entity.auth.Resource;
import com.nanxing.kubeguard.entity.auth.ServiceAccount;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Author: Nanxing
 * Date: 2024/3/5 14:43
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Operation {
    @JSONField(ordinal = 1)
    private String auditID;

    @JSONField(ordinal = 2)
    private String operationID;

    @JSONField(ordinal = 3)
    private String serviceAccountName;

    @JSONField(ordinal = 4)
    private String serviceAccountNamespace;

    @JSONField(ordinal = 5)
    private String operation;

    @JSONField(ordinal = 6)
    private String verb;

    @JSONField(ordinal = 7)
    private String apiVersion;

    @JSONField(ordinal = 8)
    private String resourceNamespace;

    @JSONField(ordinal = 9)
    private String resource;

    @JSONField(ordinal = 10)
    private String kind;

    @JSONField(ordinal = 11)
    private String resourceName;

    @JSONField(ordinal = 12)
    private String timeStamp;

    @JSONField(ordinal = 13)
    private JSONObject operationObject;
}

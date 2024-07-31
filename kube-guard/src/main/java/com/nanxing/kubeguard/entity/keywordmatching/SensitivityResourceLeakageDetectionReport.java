package com.nanxing.kubeguard.entity.keywordmatching;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.annotation.JSONField;
import com.nanxing.kubeguard.entity.auth.ServiceAccount;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Author: Nanxing
 * Date: 2024/3/24 10:05
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SensitivityResourceLeakageDetectionReport {
    @JSONField(ordinal = 1)
    private boolean isLeakage;

    @JSONField(ordinal = 2)
    private String srcIp;

    @JSONField(ordinal = 3)
    private String srcAccount;

    @JSONField(ordinal = 4)
    private String dstIp;

    @JSONField(ordinal = 5)
    private String dstAccount;

    @JSONField(ordinal = 6)
    private LeakageDetail request;

    @JSONField(ordinal = 7)
    private LeakageDetail response;

    @JSONField(ordinal = 8)
    private JSONObject packet;
}

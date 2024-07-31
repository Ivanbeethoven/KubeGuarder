package com.nanxing.kubeguard.entity.webhook;

import com.alibaba.fastjson.JSONObject;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Author: Nanxing
 * Date: 2024/3/14 20:02
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AR_Request {
    private String uid;

    private AR_Kind kind;
    private AR_Resource resource;
    private String subResource;

    private AR_Kind requestKind;
    private AR_Resource requestResource;
    private String requestSubResource;

    private String name;
    private String namespace;
    private String operation;
    private AR_UserInfo userInfo;
    private JSONObject object;
    private JSONObject oldObject;
}

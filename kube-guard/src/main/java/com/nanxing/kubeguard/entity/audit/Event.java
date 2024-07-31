package com.nanxing.kubeguard.entity.audit;

import com.alibaba.fastjson.JSONObject;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * Author: Nanxing
 * Date: 2024/3/5 10:29
 */
@NoArgsConstructor
@AllArgsConstructor
@Data
public class Event {
    private String apiVersion;
    private String kind;
    private String level;
    private String timestamp;
    private String auditID;
    private String stage;
    private String requestURI;
    private String verb;
    private UserInfo user;
    private UserInfo impersonatedUser;
    private List<String> sourceIPs;
    private ObjectRef objectRef;
    private ResponseStatus responseStatus;
    private Map<String, String> annotations;
    private JSONObject requestObject;
    private JSONObject responseObject;
}

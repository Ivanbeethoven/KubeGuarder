package com.nanxing.kubeguard.entity.runtimecheck;

import com.alibaba.fastjson.JSONObject;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Author: Nanxing
 * Date: 2024/4/11 22:35
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class DynamicDTO {
    private String operationId;
    private List<String> typeList;
    private String account;
    private String verb;
    private String resource;
    private String timestamp;
    private DynamicDetectionReport report;

    public DynamicDTO(DynamicDetectionReport report) {
        String auditID = report.getOperation().getAuditID();
        String operationID = report.getOperation().getOperationID();
        if(auditID != null && !auditID.isEmpty()){
            this.operationId = auditID;

        }else{
            this.operationId = operationID;
        }

        this.typeList = new ArrayList<>();
        for (PrivilegeEscalationType privilegeEscalationType : report.getTypeList()) {
            String type = privilegeEscalationType.getType();
            this.typeList.add(type);
        }
        this.account = report.getOperation().getServiceAccountNamespace() + "/" + report.getOperation().getServiceAccountName();
        this.verb = report.getOperation().getVerb();
        if(this.verb == null){
            this.verb = report.getOperation().getOperation().toLowerCase(Locale.ROOT);
        }
        StringBuilder sb = new StringBuilder();
        String apiVersion = report.getOperation().getApiVersion();
        String kind = report.getOperation().getKind();
        String resource = report.getOperation().getResource();
        String resourceNamespace = report.getOperation().getResourceNamespace();
        String resourceName = report.getOperation().getResourceName();
        if(apiVersion != null && !apiVersion.equals("")){
            sb.append(report.getOperation().getApiVersion());
            sb.append("/");
        }
        if(resourceNamespace != null){
            sb.append(resourceNamespace).append("/");
        }
        if(resource != null){
            sb.append(resource);
            sb.append("/");
        }else if(kind != null){
            sb.append(kind);
            sb.append("/");
        }
        if(resourceName == null && sb.length() > 0){
            sb.deleteCharAt(sb.length() - 1);
        }else{
            sb.append(resourceName);
        }
        this.resource = sb.toString();
        this.timestamp = report.getOperation().getTimeStamp();
        this.report = report;
    }
}

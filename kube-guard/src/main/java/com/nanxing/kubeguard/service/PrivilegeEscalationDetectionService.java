package com.nanxing.kubeguard.service;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.nanxing.kubeguard.client.KubernetesClient;
import com.nanxing.kubeguard.entity.audit.Event;
import com.nanxing.kubeguard.entity.audit.ObjectRef;
import com.nanxing.kubeguard.entity.auth.*;
import com.nanxing.kubeguard.entity.runtimecheck.DynamicDetectionReport;
import com.nanxing.kubeguard.entity.runtimecheck.Operation;
import com.nanxing.kubeguard.entity.runtimecheck.PrivilegeEscalationType;
import com.nanxing.kubeguard.utils.KubeTypeUtils;
import com.nanxing.kubeguard.utils.RedisCache;
import com.nanxing.kubeguard.websocket.EscalationWebSocketServer;
import io.kubernetes.client.openapi.models.V1PolicyRule;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Author: Nanxing
 * Date: 2024/3/6 15:31
 */
@Service
@Slf4j
public class PrivilegeEscalationDetectionService {

    @Autowired
    private KubernetesClient kubernetesClient;

    @Autowired
    private KubernetesContext kubernetesContext;

    @Autowired
    private RedisTemplate redisTemplate;


    @Async
    public void detectEvent(Event event){
        event = this.filterEvent(event);
        if(event == null){
            return;
        }
        ServiceAccount serviceAccount = findServiceAccountFromEvent(event);
        if(serviceAccount == null){
            return;
        }
        String serviceAccountName = serviceAccount.getName();
        String serviceAccountNamespace = serviceAccount.getNamespace();

        //先初始化检测结果
        DynamicDetectionReport report = new DynamicDetectionReport();
        report.setOverPrivilege(false);
        report.setTypeList(new ArrayList<>());
        Operation operation = new Operation();
        operation.setAuditID(event.getAuditID());
        operation.setServiceAccountName(serviceAccountName);
        operation.setServiceAccountNamespace(serviceAccountNamespace);
        ObjectRef objectRef = event.getObjectRef();
        if(objectRef != null){
            operation.setResource(objectRef.getResource());
            operation.setResourceName(objectRef.getName());
            operation.setResourceNamespace(objectRef.getNamespace());
            operation.setApiVersion(objectRef.getApiVersion());
        }
        operation.setVerb(event.getVerb());
        operation.setTimeStamp(event.getTimestamp());
        operation.setOperationObject(event.getRequestObject());
        report.setOperation(operation);


        //检测 凭证窃取
        if(isCredentialStealing(event, serviceAccount, report)){
            log.warn("[{}] 窃取了 {}:{} 的凭证", event.getSourceIPs().get(0), serviceAccountNamespace, serviceAccountName);
        }
        if(isImpersonate(event, serviceAccount, report)){
            log.warn("[{}:{}] 伪装了 [{}], 并执行了越权操作", serviceAccountNamespace, serviceAccountName, event.getImpersonatedUser().getUsername());
        }
        if(isIndirectExecution(event, serviceAccount, report)){
            log.warn("[{}:{}] 操作了其他账户下的负载，但没有其全部权限", serviceAccountNamespace, serviceAccountName );
        }

        //如果没有越权行为，则列表设为null
        if(report.getTypeList().isEmpty()){
            report.setTypeList(null);
        }
        //返回和持久化检测结果
        if(report.isOverPrivilege()){
            writeReportToRedis(report, "kube-guard:dynamic-detection:event-reports");
            sendReportToWSClient(report);
        }

    }

    public void detectAdmissionReview(JSONObject admissionReview){
        //过滤
        JSONObject request = admissionReview.getJSONObject("request");

        JSONObject userInfo = request.getJSONObject("userInfo");
        String username = userInfo.getString("username");
        if(!username.startsWith("system:serviceaccount:")){
            return;
        }
        String[] splited = username.split(":");
        String serviceAccountName = splited[3];
        String serviceAccountNamespace = splited[2];

        Optional<ServiceAccount> optionalServiceAccount = kubernetesContext.serviceAccountList.stream()
                .filter(serviceAccount -> serviceAccount.getNamespace().equals(serviceAccountNamespace))
                .filter(serviceAccount -> serviceAccount.getName().equals(serviceAccountName))
                .findAny();
        if(!optionalServiceAccount.isPresent()){
            return ;
        }
        ServiceAccount serviceAccount = optionalServiceAccount.get();

        //初始化Report
        DynamicDetectionReport report = new DynamicDetectionReport();
        report.setOverPrivilege(false);
        report.setTypeList(new ArrayList<>());
        Operation operation = new Operation();
        operation.setOperation(request.getString("operation"));
        operation.setOperationID(request.getString("uid"));
        operation.setKind(request.getJSONObject("requestKind").getString("kind"));
        operation.setResource(request.getJSONObject("resource").getString("resource"));
        String group = request.getJSONObject("resource").getString("group");
        String version = request.getJSONObject("resource").getString("version");

        if(group != null && !group.isEmpty()){
            operation.setApiVersion(group + "/" + version);
        }else{
            operation.setApiVersion(version);
        }
        if(request.containsKey("namespace")){
            operation.setResourceNamespace(request.getString("namespace"));
        }
        if(request.containsKey("name")){
            operation.setResourceName(request.getString("name"));
        }
        operation.setServiceAccountNamespace(serviceAccountNamespace);
        operation.setServiceAccountName(serviceAccountName);

        // 获取当前日期时间
        LocalDateTime now = LocalDateTime.now();
        // 定义ISO 8601日期时间格式
        DateTimeFormatter formatter = DateTimeFormatter.ISO_DATE_TIME;
        // 格式化当前日期时间
        String formattedDateTime = now.format(formatter);
        operation.setTimeStamp(formattedDateTime);
        operation.setOperationObject(request.getJSONObject("object"));
        report.setOperation(operation);

        //检测操作RBAC越权
        if(isOperateRBAC(admissionReview, serviceAccount, report)){
            log.warn("The service account [{}:{}] operated RBAC beyond authority", serviceAccountNamespace, serviceAccountName);
        }

        //返回和持久化检测结果
        if(report.isOverPrivilege()){
            writeReportToRedis(report, "kube-guard:dynamic-detection:admission-review-reports");
            sendReportToWSClient(report);
        }

    }




    public boolean isCredentialStealing(Event event, ServiceAccount serviceAccount, DynamicDetectionReport report){
        List<String> sourceIPs = event.getSourceIPs();

        //网络策略补丁
        for (String nodeIp : kubernetesContext.nodeIpList) {
            for (String sourceIP : sourceIPs) {
                if(nodeIp.equals(sourceIP)){
                    return false;
                }
            }
        }
        List<String> podIPList = serviceAccount.getPodList().stream()
                .map(Pod::getIp)
                .collect(Collectors.toList());
        podIPList.retainAll(sourceIPs);
        if(podIPList.isEmpty()){
            report.setOverPrivilege(true);
            PrivilegeEscalationType privilegeEscalationType = new PrivilegeEscalationType();
            privilegeEscalationType.setType(PrivilegeEscalationType.STEALING_CREDENTIALS);
            System.out.println(JSONObject.toJSONString(event, true));
            String message = "Client [" + sourceIPs.get(0)  + "] carried an unexpected credential that is of [" + serviceAccount.getNamespace() + ":" + serviceAccount.getName() + "]";
            privilegeEscalationType.setMessage(message);
            report.getTypeList().add(privilegeEscalationType);
            return true;
        }
        return false;
    }

    public boolean isImpersonate(Event event, ServiceAccount serviceAccount, DynamicDetectionReport report){
        if(event.getImpersonatedUser() == null){
            return false;
        }

        ObjectRef objectRef = event.getObjectRef();
        String verb = event.getVerb();
        String resourceClass = objectRef.getResource();
        String resourceNamespace = objectRef.getNamespace();
        String resourceName = objectRef.getName();
        String resourceApiVersion = objectRef.getApiVersion();
        String resourceApiGroup = resourceApiVersion.contains("/") ? resourceApiVersion.split("/")[0] : "";


        //验证集群角色的权限
        List<ClusterRole> clusterRoleList = serviceAccount.getClusterRoleList();
        List<Rule> ruleList = clusterRoleList.stream()
                .flatMap((Function<ClusterRole, Stream<Rule>>) clusterRole -> clusterRole.getRuleList().stream())
                .collect(Collectors.toList());

        for (Rule rule : ruleList) {
            List<String> nonResourceURLs = rule.getNonResourceURLs();
            if(nonResourceURLs != null && !nonResourceURLs.isEmpty()){
                continue;
            }
            List<String> apiGroups = rule.getApiGroups();
            List<String> classes = rule.getClasses();
            List<String> resourceNames = rule.getResourceNames();
            List<String> verbs = rule.getVerbs();
            if(apiGroups.contains(resourceApiGroup) || apiGroups.contains("*")){
                if(classes.contains(resourceClass) || resourceClass.contains("*")){
                    if(resourceName == null || resourceNames == null || resourceNames.contains(resourceName) || resourceNames.contains("*")){
                        if(verbs.contains("*") || verbs.contains(verb)){
                            return false;
                        }
                    }
                }
            }
        }

        //如果命名空间为空，说明是集群级别资源，无需验证非集群角色列表
        if(resourceNamespace != null){
            List<Role> roleList = serviceAccount.getRoleList();
            for (Role role : roleList) {
                String roleNamespace = role.getNamespace();
                if(!roleNamespace.equals(resourceNamespace)){
                    continue;
                }
                List<Rule> ruleList1 = role.getRuleList();
                for (Rule rule : ruleList1) {
                    List<String> nonResourceURLs = rule.getNonResourceURLs();
                    if(nonResourceURLs != null && !nonResourceURLs.isEmpty()){
                        continue;
                    }
                    List<String> apiGroups = rule.getApiGroups();
                    List<String> classes = rule.getClasses();
                    List<String> resourceNames = rule.getResourceNames();
                    List<String> verbs = rule.getVerbs();
                    if(apiGroups.contains(resourceApiGroup) || apiGroups.contains("*")){
                        if(classes.contains(resourceClass) || resourceClass.contains("*")){
                            if(resourceName == null || resourceNames == null || resourceNames.contains(resourceName) || resourceNames.contains("*")){
                                if(verbs.contains("*") || verbs.contains(verb)){
                                    return false;
                                }
                            }
                        }
                    }
                }
            }
        }

        report.setOverPrivilege(true);
        PrivilegeEscalationType privilegeEscalationType = new PrivilegeEscalationType();
        privilegeEscalationType.setType(PrivilegeEscalationType.IMPERSONATE_ACCOUNTS);
        String message = "The account [" + serviceAccount.getNamespace() + ":" + serviceAccount.getName() + "] performed an unauthorized operation by impersonating ["
                + event.getImpersonatedUser().getUsername() + "]";
        privilegeEscalationType.setMessage(message);
        report.getTypeList().add(privilegeEscalationType);
        return true;
    }

    public boolean isOperateRBAC(Event event){
        String verb = event.getVerb();
        if(!("create".equals(verb) || "update".equals(verb) || "patch".equals(verb))){
            return false;
        }

        ServiceAccount serviceAccount = findServiceAccountFromEvent(event);
        if(serviceAccount == null){
            return false;
        }

        ObjectRef objectRef = event.getObjectRef();
        String resourceClass = objectRef.getResource();
        switch (resourceClass){
            case "roles":{
                //String roleName = objectRef.getName();
                String roleNamespace = objectRef.getNamespace();
                JSONObject requestObject = event.getRequestObject();
                List<Rule> ruleList = getRuleListFromRequestObject(requestObject);
                if(ruleList.isEmpty()){
                    return false;
                }
                for (Rule rule : ruleList) {
                    if(!isBelong(serviceAccount, rule, roleNamespace)){
                        return true;
                    }

                }
                return false;
            }
            case "clusterroles":{
                //String clusterroleName = objectRef.getName();
                JSONObject requestObject = event.getRequestObject();
                List<Rule> ruleList = getRuleListFromRequestObject(requestObject);
                if(ruleList.isEmpty()){
                    return false;
                }
                for (Rule rule : ruleList) {
                    if(!isBelong(serviceAccount, rule))
                        return true;
                }
                return false;
            }
            case "rolebindings":{
                String rolebindingNamespace = objectRef.getNamespace();
                JSONObject requestObject = event.getRequestObject();
                if(!requestObject.containsKey("roleRef")){
                    return false;
                }
                JSONObject roleRef = requestObject.getJSONObject("roleRef");
                String kind = roleRef.getString("kind");
                List<Rule> ruleList = null;
                if("Role".equals(kind)){
                    Role role = kubernetesClient.getOneRole(rolebindingNamespace, roleRef.getString("name"));
                    if(role == null){
                        return false;
                    }
                    ruleList = role.getRuleList();
                }else if("ClusterRole".equals(kind)){
                    ClusterRole clusterRole = kubernetesClient.getOneClusterRole(roleRef.getString("name"));
                    if(clusterRole == null){
                        return false;
                    }
                    ruleList = clusterRole.getRuleList();
                }
                if(ruleList == null || ruleList.isEmpty()){
                    return false;
                }
                for (Rule rule : ruleList) {
                    if(!isBelong(serviceAccount, rule, rolebindingNamespace))
                        return true;
                }
                return false;
            }
            case "clusterrolebindings":{
                JSONObject requestObject = event.getRequestObject();
                if(!requestObject.containsKey("roleRef")){
                    return false;
                }
                JSONObject roleRef = requestObject.getJSONObject("roleRef");

                ClusterRole clusterRole = kubernetesClient.getOneClusterRole(roleRef.getString("name"));
                if(clusterRole == null){
                    return false;
                }
                List<Rule> ruleList = clusterRole.getRuleList();

                if(ruleList == null || ruleList.isEmpty()){
                    return false;
                }
                for (Rule rule : ruleList) {
                    if(!isBelong(serviceAccount, rule))
                        return true;
                }
                return false;

            }
        }
        return false;

    }

    public boolean isOperateRBAC(JSONObject admissionReview, ServiceAccount serviceAccount, DynamicDetectionReport report){
        JSONObject request = admissionReview.getJSONObject("request");

        JSONObject requestResource = request.getJSONObject("requestResource");
        String resourceClass = requestResource.getString("resource");
        switch (resourceClass){
            case "roles":{
                //String roleName = objectRef.getName();
                String roleNamespace = request.getString("namespace");
                JSONObject requestObject = request.getJSONObject("object");
                List<Rule> ruleList = getRuleListFromRequestObject(requestObject);
                if(ruleList.isEmpty()){
                    return false;
                }
                for (Rule rule : ruleList) {
                    if(!isBelong(serviceAccount, rule, roleNamespace)){
                        report.setOverPrivilege(true);
                        PrivilegeEscalationType privilegeEscalationType = new PrivilegeEscalationType();
                        privilegeEscalationType.setType(PrivilegeEscalationType.OPERATING_RBAC);
                        String message = "The account [" + serviceAccount.getNamespace() + ":" + serviceAccount.getName() + "] has not held the authority " + rule.toString() + " of namespace [" + roleNamespace + "]";
                        privilegeEscalationType.setMessage(message);
                        report.getTypeList().add(privilegeEscalationType);

                        return true;
                    }

                }
                return false;
            }
            case "clusterroles":{
                //String clusterroleName = objectRef.getName();
                JSONObject requestObject = request.getJSONObject("object");
                List<Rule> ruleList = getRuleListFromRequestObject(requestObject);
                if(ruleList.isEmpty()){
                    return false;
                }
                for (Rule rule : ruleList) {
                    if(!isBelong(serviceAccount, rule)){
                        report.setOverPrivilege(true);
                        PrivilegeEscalationType privilegeEscalationType = new PrivilegeEscalationType();
                        privilegeEscalationType.setType(PrivilegeEscalationType.OPERATING_RBAC);
                        String message = "The account [" + serviceAccount.getNamespace() + ":" + serviceAccount.getName() + "] has not held the cluster-level authority " + rule.toString();
                        privilegeEscalationType.setMessage(message);
                        report.getTypeList().add(privilegeEscalationType);
                        return true;
                    }

                }
                return false;
            }
            case "rolebindings":{
                String rolebindingNamespace = request.getString("namespace");
                JSONObject requestObject = request.getJSONObject("object");
                if(!requestObject.containsKey("roleRef")){
                    return false;
                }
                JSONObject roleRef = requestObject.getJSONObject("roleRef");
                String kind = roleRef.getString("kind");
                List<Rule> ruleList = null;
                if("Role".equals(kind)){
                    Role role = kubernetesClient.getOneRole(rolebindingNamespace, roleRef.getString("name"));
                    if(role == null){
                        return false;
                    }
                    ruleList = role.getRuleList();
                }else if("ClusterRole".equals(kind)){
                    ClusterRole clusterRole = kubernetesClient.getOneClusterRole(roleRef.getString("name"));
                    if(clusterRole == null){
                        return false;
                    }
                    ruleList = clusterRole.getRuleList();
                }
                if(ruleList == null || ruleList.isEmpty()){
                    return false;
                }
                for (Rule rule : ruleList) {
                    if(!isBelong(serviceAccount, rule, rolebindingNamespace)){
                        report.setOverPrivilege(true);
                        PrivilegeEscalationType privilegeEscalationType = new PrivilegeEscalationType();
                        privilegeEscalationType.setType(PrivilegeEscalationType.OPERATING_RBAC);
                        String message = "The account [" + serviceAccount.getNamespace() + ":" + serviceAccount.getName() + "] has not held the authority " + rule.toString() + " of namespace [" + rolebindingNamespace + "]";
                        privilegeEscalationType.setMessage(message);
                        report.getTypeList().add(privilegeEscalationType);
                        return true;
                    }

                }
                return false;
            }
            case "clusterrolebindings":{
                JSONObject requestObject = request.getJSONObject("object");
                if(!requestObject.containsKey("roleRef")){
                    return false;
                }
                JSONObject roleRef = requestObject.getJSONObject("roleRef");

                ClusterRole clusterRole = kubernetesClient.getOneClusterRole(roleRef.getString("name"));
                if(clusterRole == null){
                    return false;
                }
                List<Rule> ruleList = clusterRole.getRuleList();

                if(ruleList == null || ruleList.isEmpty()){
                    return false;
                }
                for (Rule rule : ruleList) {
                    if(!isBelong(serviceAccount, rule)){
                        report.setOverPrivilege(true);
                        PrivilegeEscalationType privilegeEscalationType = new PrivilegeEscalationType();
                        privilegeEscalationType.setType(PrivilegeEscalationType.OPERATING_RBAC);
                        String message = "The account [" + serviceAccount.getNamespace() + ":" + serviceAccount.getName() + "] has not held the cluster-level authority " + rule.toString();
                        privilegeEscalationType.setMessage(message);
                        report.getTypeList().add(privilegeEscalationType);
                        return true;
                    }

                }
                return false;

            }
        }
        return false;
    }




    public boolean isIndirectExecution(Event event, ServiceAccount serviceAccount, DynamicDetectionReport report){
        String verb = event.getVerb();
        if(!("create".equals(verb) || "update".equals(verb) || "patch".equals(verb))){
            return false;
        }

        ObjectRef objectRef = event.getObjectRef();
        String aclass = objectRef.getResource();

        if(!("pods".equals(aclass) || "deployments".equals(aclass) || "replicasets".equals(aclass) || "statefulsets".equals(aclass) || "daemonsets".equals(aclass) || "job".equals(aclass) || "cronjobs".equals(aclass))){
            return false;
        }
        String resourceNamespace = objectRef.getNamespace();
        JSONObject requestObject = event.getRequestObject();

        //获取pod绑定的服务账户名
        String bindServiceAccountName = null;
        if(aclass.equals("pods")){
            //如果没有spec字段
            if(!requestObject.containsKey("spec")){
                return false;
            }
            JSONObject spec = requestObject.getJSONObject("spec");
            if(!spec.containsKey("serviceAccountName")){
                bindServiceAccountName = "default";
            }else{
                bindServiceAccountName = spec.getString("serviceAccountName");
            }
        }else if(aclass.equals("cronjobs")){
            //如果没有spec字段
            if(!requestObject.containsKey("spec")){
                return false;
            }
            JSONObject spec = requestObject.getJSONObject("spec");
            if(!spec.containsKey("jobTemplate")){
                return false;
            }
            JSONObject jobTemplate = spec.getJSONObject("jobTemplate");
            if(!jobTemplate.containsKey("spec")){
                return false;
            }
            JSONObject jobSpec = jobTemplate.getJSONObject("spec");
            if(!jobSpec.containsKey("template")){
                return false;
            }
            JSONObject template = jobSpec.getJSONObject("template");
            if(!template.containsKey("spec")){
                return false;
            }
            JSONObject podSpec = template.getJSONObject("spec");
            if(podSpec.containsKey("serviceAccountName")){
                bindServiceAccountName = podSpec.getString("serviceAccountName");
            }else{
                bindServiceAccountName = "default";
            }
        }else{
            //如果没有spec字段
            if(!requestObject.containsKey("spec")){
                return false;
            }
            JSONObject spec = requestObject.getJSONObject("spec");
            if(!spec.containsKey("template")){
                return false;
            }
            JSONObject template = spec.getJSONObject("template");
            if(!template.containsKey("spec")){
                return false;
            }
            JSONObject podSpec = template.getJSONObject("spec");
            if(podSpec.containsKey("serviceAccountName")){
                bindServiceAccountName = podSpec.getString("serviceAccountName");
            }else{
                bindServiceAccountName = "default";
            }
        }

        if(bindServiceAccountName == null){
            return false;
        }
        String finalBindServiceAccountName = bindServiceAccountName;
        Optional<ServiceAccount> optionalBindServiceAccount = this.kubernetesContext.serviceAccountList.stream()
                .filter(serviceAccount1 -> resourceNamespace.equals(serviceAccount1.getNamespace()) && finalBindServiceAccountName.equals(serviceAccount1.getName()))
                .findFirst();

        //如果没有记录该服务账户
        if(!optionalBindServiceAccount.isPresent()){
            return false;
        }
        ServiceAccount bindServiceAccount = optionalBindServiceAccount.get();

        //判断bindServiceAccount拥有的权限是否是serviceAccount的子集
        List<Role> roleList = bindServiceAccount.getRoleList();
        if(roleList != null){
            for (Role role : roleList) {
                List<Rule> ruleList = role.getRuleList();
                if(ruleList != null){
                    for (Rule rule : ruleList) {
                        if(!isBelong(serviceAccount, rule, resourceNamespace)){
                            report.setOverPrivilege(true);
                            PrivilegeEscalationType privilegeEscalationType = new PrivilegeEscalationType();
                            privilegeEscalationType.setType(PrivilegeEscalationType.INDIRECT_EXECUTION);
                            String message = "The account [" + serviceAccount.getNamespace() + ":" + serviceAccount.getName() + "] has not held the privilege " +
                                    rule.toString() + " of [" + bindServiceAccount.getNamespace() + ":" + bindServiceAccountName + "]";
                            privilegeEscalationType.setMessage(message);
                            report.getTypeList().add(privilegeEscalationType);
                            return true;
                        }
                    }
                }
            }
        }
        List<ClusterRole> clusterRoleList = bindServiceAccount.getClusterRoleList();
        if(clusterRoleList != null){
            for (ClusterRole clusterRole : clusterRoleList) {
                List<Rule> ruleList = clusterRole.getRuleList();
                if(ruleList != null){
                    for (Rule rule : ruleList) {
                        if(!isBelong(serviceAccount, rule)){
                            report.setOverPrivilege(true);
                            PrivilegeEscalationType privilegeEscalationType = new PrivilegeEscalationType();
                            privilegeEscalationType.setType(PrivilegeEscalationType.INDIRECT_EXECUTION);
                            String message = "The account [" + serviceAccount.getNamespace() + ":" + serviceAccount.getName() + "] has not held the privilege " +
                                    rule.toString() + " of [" + bindServiceAccount.getNamespace() + ":" + bindServiceAccountName + "]";
                            privilegeEscalationType.setMessage(message);
                            report.getTypeList().add(privilegeEscalationType);
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    public ServiceAccount findServiceAccountFromEvent(Event event){
        // 只需要 ResponseComplete 阶段的日志
        if(!"ResponseComplete".equals(event.getStage())){
            return null;
        }
        // 不检测失败的操作
        if("300".compareTo(event.getResponseStatus().getCode()) <= 0){
            return null;
        }
        String username = event.getUser().getUsername();
        if(!username.startsWith("system:serviceaccount:")){
            return null;
        }
        String[] splited = username.split(":");
        String serviceAccountName = splited[3];
        String serviceAccountNamespace = splited[2];
        // log.info("670:The service account [{}:{}] operated RBAC beyond authority", serviceAccountNamespace, serviceAccountName);
        //log.info("671:kubernetesContext.serviceAccountList  is {}", kubernetesContext.serviceAccountList==null);//kubernetesContext.serviceAccountList  is true
        Optional<ServiceAccount> optionalServiceAccount = kubernetesContext.serviceAccountList.stream()
                .filter(serviceAccount -> serviceAccountNamespace.equals(serviceAccount.getNamespace()))
                .filter(serviceAccount -> serviceAccountName.equals(serviceAccount.getName()))
                .findAny();
        return optionalServiceAccount.orElse(null);
    }



    //判断服务账户是否拥有命名空间级别权限
    public boolean isBelong(ServiceAccount serviceAccount, Rule rule, String namespace){
        if(rule.getNonResourceURLs() != null && !rule.getNonResourceURLs().isEmpty()){
            return true;
        }
        List<MetaRule> metaRuleList = rule2MetaRuleList(rule); //转为单条的权限条目
        List<Role> roleList = serviceAccount.getRoleList();
        List<ClusterRole> clusterRoleList = serviceAccount.getClusterRoleList();
        for (Role role : roleList) {
            if(!namespace.equals(role.getNamespace())){
                continue;
            }
            List<Rule> ruleList = role.getRuleList();
            for (Rule heldRule : ruleList) {
                metaRuleList = filterMetaRuleList(metaRuleList, heldRule);
                if(metaRuleList.isEmpty()){
                    return true;
                }
            }
        }
        for (ClusterRole clusterRole : clusterRoleList){
            List<Rule> ruleList = clusterRole.getRuleList();
            for (Rule heldRule : ruleList) {
                metaRuleList = filterMetaRuleList(metaRuleList, heldRule);
                if(metaRuleList.isEmpty()){
                    return true;
                }
            }
        }
        for (MetaRule metaRule : metaRuleList) {
            log.warn("Permission Rule [{}] has not been held by [{}:{}]", metaRule, serviceAccount.getNamespace(), serviceAccount.getName());
        }
        return false;
    }

    //判断服务账户是否拥有集群级别权限
    public boolean isBelong(ServiceAccount serviceAccount, Rule rule){
        if(rule.getNonResourceURLs() != null && !rule.getNonResourceURLs().isEmpty()){
            return true;
        }
        List<MetaRule> metaRuleList = rule2MetaRuleList(rule); //转为单条的权限条目
        List<ClusterRole> clusterRoleList = serviceAccount.getClusterRoleList();
        for (ClusterRole clusterRole : clusterRoleList){
            List<Rule> ruleList = clusterRole.getRuleList();
            for (Rule heldRule : ruleList) {
                metaRuleList = filterMetaRuleList(metaRuleList, heldRule);
                if(metaRuleList.isEmpty()){
                    return true;
                }
            }
        }
        for (MetaRule metaRule : metaRuleList) {
            log.warn("Permission Rule [{}] has not been held by [{}:{}]", metaRule, serviceAccount.getNamespace(), serviceAccount.getName());
        }
        return false;
    }


    public List<MetaRule> filterMetaRuleList(List<MetaRule> metaRuleList, Rule rule){
        if(rule.getNonResourceURLs() != null && !rule.getNonResourceURLs().isEmpty())
            return metaRuleList;
        if(metaRuleList.isEmpty())
            return metaRuleList;
        return metaRuleList.stream()
                .filter(metaRule -> {
                    boolean hasIntersection = hasIntersection(metaRule.getApiGroups(), rule.getApiGroups());
                    if(!rule.getApiGroups().contains("*") && !hasIntersection){
                        return true;
                    }
                    boolean flag1 = rule.getClasses().contains(metaRule.getKind()) || rule.getClasses().contains("*");
                    boolean flag2 = rule.getVerbs().contains(metaRule.getVerb()) || rule.getVerbs().contains("*");
                    boolean flag3 = false;
                    List<String> resourceNames = rule.getResourceNames();
                    String resourceName = metaRule.getResourceName();
                    if(rule.getResourceNames() == null || rule.getResourceNames().isEmpty()){
                        flag3 = true;
                    }else if(resourceName != null && (resourceNames.contains("*") || resourceNames.contains(resourceName))){
                        flag3 = true;
                    }
                    return !(flag1 && flag2 && flag3);
                }).collect(Collectors.toList());
    }

    public List<MetaRule> rule2MetaRuleList(Rule rule){
        List<MetaRule> metaRuleList =  new ArrayList<>();
        if(rule.getNonResourceURLs() != null && !rule.getNonResourceURLs().isEmpty()){
            return metaRuleList;
        }
        if(rule.getResourceNames() != null && !rule.getResourceNames().isEmpty()){
            for (String aClass : rule.getClasses()) {
                for (String verb : rule.getVerbs()) {
                    for (String resourceName : rule.getResourceNames()) {
                        MetaRule metaRule = new MetaRule();
                        metaRule.setApiGroups(new ArrayList<>(rule.getApiGroups()));
                        metaRule.setKind(aClass);
                        metaRule.setVerb(verb);
                        metaRule.setResourceName(resourceName);
                        metaRuleList.add(metaRule);
                    }
                }
            }
        }else{
            for (String aClass : rule.getClasses()) {
                for (String verb : rule.getVerbs()) {
                    MetaRule metaRule = new MetaRule();
                    metaRule.setApiGroups(rule.getApiGroups());
                    metaRule.setKind(aClass);
                    metaRule.setVerb(verb);
                    metaRule.setResourceName(null);
                    metaRuleList.add(metaRule);
                }
            }
        }
        return metaRuleList;
    }

    public List<Rule> getRuleListFromRequestObject(JSONObject requestObject){
        List<Rule> ruleList = new ArrayList<>();
        if(!requestObject.containsKey("rules")){
            return ruleList;
        }
        List<V1PolicyRule> v1PolicyRuleList = requestObject.getJSONArray("rules").toJavaList(V1PolicyRule.class);
        ruleList = v1PolicyRuleList.stream().map(v1PolicyRule -> {
            Rule rule = new Rule();
            rule.setApiGroups(v1PolicyRule.getApiGroups());
            rule.setClasses(v1PolicyRule.getResources());
            rule.setResourceNames(v1PolicyRule.getResourceNames());
            rule.setVerbs(v1PolicyRule.getVerbs());
            rule.setNonResourceURLs(v1PolicyRule.getNonResourceURLs());
            return rule;
        }).collect(Collectors.toList());
        return ruleList;
    }

    public boolean hasIntersection(List<String> list1, List<String> list2) {
        // 创建两个 HashSet 分别存储 list1 和 list2 中的所有元素
        Set<String> set1 = new HashSet<>(list1);
        Set<String> set2 = new HashSet<>(list2);

        // 判断两个 HashSet 是否有交集
        return !set1.isEmpty() && !set2.isEmpty() && !Collections.disjoint(set1, set2);
    }

    private Event filterEvent(Event event){
        // 只需要 ResponseComplete 阶段的日志
        if(!"ResponseComplete".equals(event.getStage())){
            return null;
        }
        // 不检测失败的操作
        if("300".compareTo(event.getResponseStatus().getCode()) <= 0){
            return null;
        }
        return event;
    }

    @Async
    public void writeReportToRedis(DynamicDetectionReport report, String key){
        this.redisTemplate.opsForList().rightPush("kube-guard:dynamic-detection:escalation-reports", report);
    }

    @Async
    public void sendReportToWSClient(DynamicDetectionReport report){
        try {
            EscalationWebSocketServer.sendMessage(JSONObject.toJSONString(report), null);
        } catch (IOException e) {
            log.info("检测结果发送失败");
            e.printStackTrace();
        }
    }





}

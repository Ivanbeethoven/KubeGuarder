package com.nanxing.kubeguard.utils;

import com.alibaba.fastjson.JSON;
import com.nanxing.kubeguard.entity.audit.Event;
import com.nanxing.kubeguard.entity.auth.ClusterRole;
import com.nanxing.kubeguard.entity.auth.Role;
import com.nanxing.kubeguard.entity.auth.Rule;
import io.kubernetes.client.openapi.models.V1ClusterRole;
import io.kubernetes.client.openapi.models.V1PolicyRule;
import io.kubernetes.client.openapi.models.V1Role;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Author: Nanxing
 * Date: 2024/3/5 15:00
 */
//用于转换KubernetesAPI数据类型
public class KubeTypeUtils {


    public static Event jsonStrToEvent(String json){
        Event event = null;
        event = JSON.parseObject(json, Event.class);
        return event;
    }

    public static Role v1Role2Role(V1Role v1Role){
        Role role = new Role();
        role.setName(v1Role.getMetadata().getName());
        role.setNamespace(v1Role.getMetadata().getNamespace());
        List<Rule> ruleList = new ArrayList<>();

        for (V1PolicyRule v1Rule : v1Role.getRules()) {
            Rule rule = new Rule();
            rule.setClasses(v1Rule.getResources());
            rule.setApiGroups(v1Rule.getApiGroups());
            rule.setResourceNames(v1Rule.getResourceNames());
            rule.setVerbs(v1Rule.getVerbs());
            rule.setNonResourceURLs(v1Rule.getNonResourceURLs());
            ruleList.add(rule);
        }
        role.setRuleList(ruleList);
        return role;
    }

    public static ClusterRole v1ClusterRole2ClusterRole(V1ClusterRole v1ClusterRole){
        ClusterRole clusterRole = new ClusterRole();
        clusterRole.setName(v1ClusterRole.getMetadata().getName());
        List<Rule> ruleList = v1ClusterRole.getRules().stream().map(v1PolicyRule -> {
            Rule rule = new Rule();
            rule.setApiGroups(v1PolicyRule.getApiGroups());
            rule.setClasses(v1PolicyRule.getResources());
            rule.setResourceNames(v1PolicyRule.getResourceNames());
            rule.setVerbs(v1PolicyRule.getVerbs());
            rule.setNonResourceURLs(v1PolicyRule.getNonResourceURLs());
            return rule;
        }).collect(Collectors.toList());
        clusterRole.setRuleList(ruleList);
        return clusterRole;
    }

    public static Role v1ClusterRole2Role(V1ClusterRole v1ClusterRole, String namespace){
        Role role = new Role();
        role.setName(v1ClusterRole.getMetadata().getName());
        role.setNamespace(namespace);
        List<Rule> ruleList = v1ClusterRole.getRules().stream().map(v1PolicyRule -> {
            Rule rule = new Rule();
            rule.setApiGroups(v1PolicyRule.getApiGroups());
            rule.setClasses(v1PolicyRule.getResources());
            rule.setResourceNames(v1PolicyRule.getResourceNames());
            rule.setVerbs(v1PolicyRule.getVerbs());
            rule.setNonResourceURLs(v1PolicyRule.getNonResourceURLs());
            return rule;
        }).collect(Collectors.toList());
        role.setRuleList(ruleList);
        return role;
    }

    public static void main(String[] args) {
        String json = "{\n" +
                "    \"kind\": \"Event\",\n" +
                "    \"apiVersion\": \"audit.k8s.io/v1\",\n" +
                "    \"level\": \"RequestResponse\",\n" +
                "    \"auditID\": \"ded8c2bd-dedc-4064-a323-a0f93796a33c\",\n" +
                "    \"stage\": \"ResponseComplete\",\n" +
                "    \"requestURI\": \"/apis/authentication.k8s.io/v1/tokenreviews\",\n" +
                "    \"verb\": \"create\",\n" +
                "    \"user\": {\n" +
                "        \"username\": \"system:serviceaccount:monitoring:prometheus-adapter\",\n" +
                "        \"uid\": \"38f7ebc7-5529-4cd7-96c3-170825c22766\",\n" +
                "        \"groups\": [\n" +
                "            \"system:serviceaccounts\",\n" +
                "            \"system:serviceaccounts:monitoring\",\n" +
                "            \"system:authenticated\"\n" +
                "        ],\n" +
                "        \"extra\": {\n" +
                "            \"authentication.kubernetes.io/pod-name\": [\n" +
                "                \"prometheus-adapter-79c588b474-qrwkg\"\n" +
                "            ],\n" +
                "            \"authentication.kubernetes.io/pod-uid\": [\n" +
                "                \"6e94ba2c-6bf8-4936-8b8f-102cb0e29b83\"\n" +
                "            ]\n" +
                "        }\n" +
                "    },\n" +
                "    \"sourceIPs\": [\n" +
                "        \"192.168.117.202\"\n" +
                "    ],\n" +
                "    \"userAgent\": \"adapter/v0.0.0 (linux/amd64) kubernetes/$Format\",\n" +
                "    \"objectRef\": {\n" +
                "        \"resource\": \"tokenreviews\",\n" +
                "        \"apiGroup\": \"authentication.k8s.io\",\n" +
                "        \"apiVersion\": \"v1\"\n" +
                "    },\n" +
                "    \"responseStatus\": {\n" +
                "        \"metadata\": {},\n" +
                "        \"code\": 201\n" +
                "    },\n" +
                "    \"requestObject\": {\n" +
                "        \"kind\": \"TokenReview\",\n" +
                "        \"apiVersion\": \"authentication.k8s.io/v1\",\n" +
                "        \"metadata\": {\n" +
                "            \"creationTimestamp\": null\n" +
                "        },\n" +
                "        \"spec\": {\n" +
                "            \"token\": \"eyJhbGciOiJSUzI1NiIsImtpZCI6IlRXbjBMLUdabnk0VTlxNkV1Q2o4eW5PUjZURlFCS01XbDFFSzQ1aGNDWEkifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzM1OTA1MzQwLCJpYXQiOjE3MDQzNjkzNDAsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJtb25pdG9yaW5nIiwicG9kIjp7Im5hbWUiOiJwcm9tZXRoZXVzLWs4cy0wIiwidWlkIjoiMmFjYjY1Y2UtMWVkZS00YzE4LThhODgtOTlkYWYyNzc0NGViIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJwcm9tZXRoZXVzLWs4cyIsInVpZCI6IjA4MDE3YmZlLWZjODYtNDVhMy04Njg2LTA2NjU1MDg1MjA0NyJ9LCJ3YXJuYWZ0ZXIiOjE3MDQzNzI5NDd9LCJuYmYiOjE3MDQzNjkzNDAsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDptb25pdG9yaW5nOnByb21ldGhldXMtazhzIn0.FSnSMfUy_9HDtjROkDgqcsY1TL2TAtqtBui-uTrPai1jxJJ8MkJXreqeM57krXqugIqVbWDUhZiFCDtljnrbs67Xc1A5AJdvnxFxU73UF8uLLcGWeu0l3vORKZIyXtMLl9dz7c-w_j3bu74Qb0qnyY_OJeyKJTCQSSNhFhIQ8cr-3mQ91K8HGBB-H67HyE3exS24grCOt9UVLmmkbxJCFQ5_CnqLXZBu8b8-md6AmrHMARucm8digcYMAdanP-nNY7FftelOC2S7GCztBVA3Ur_ZaJiCgTe0WjRwUAHxW0Hxp9ZCLyZRilr8nJVgvit3LHqx_g0TDOKAAZ_XvHGhLg\"\n" +
                "        },\n" +
                "        \"status\": {\n" +
                "            \"user\": {}\n" +
                "        }\n" +
                "    },\n" +
                "    \"responseObject\": {\n" +
                "        \"kind\": \"TokenReview\",\n" +
                "        \"apiVersion\": \"authentication.k8s.io/v1\",\n" +
                "        \"metadata\": {\n" +
                "            \"creationTimestamp\": null,\n" +
                "            \"managedFields\": [\n" +
                "                {\n" +
                "                    \"manager\": \"adapter\",\n" +
                "                    \"operation\": \"Update\",\n" +
                "                    \"apiVersion\": \"authentication.k8s.io/v1\",\n" +
                "                    \"time\": \"2024-01-04T11:59:41Z\",\n" +
                "                    \"fieldsType\": \"FieldsV1\",\n" +
                "                    \"fieldsV1\": {\n" +
                "                        \"f:spec\": {\n" +
                "                            \"f:token\": {}\n" +
                "                        }\n" +
                "                    }\n" +
                "                }\n" +
                "            ]\n" +
                "        },\n" +
                "        \"spec\": {\n" +
                "            \"token\": \"eyJhbGciOiJSUzI1NiIsImtpZCI6IlRXbjBMLUdabnk0VTlxNkV1Q2o4eW5PUjZURlFCS01XbDFFSzQ1aGNDWEkifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzM1OTA1MzQwLCJpYXQiOjE3MDQzNjkzNDAsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJtb25pdG9yaW5nIiwicG9kIjp7Im5hbWUiOiJwcm9tZXRoZXVzLWs4cy0wIiwidWlkIjoiMmFjYjY1Y2UtMWVkZS00YzE4LThhODgtOTlkYWYyNzc0NGViIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJwcm9tZXRoZXVzLWs4cyIsInVpZCI6IjA4MDE3YmZlLWZjODYtNDVhMy04Njg2LTA2NjU1MDg1MjA0NyJ9LCJ3YXJuYWZ0ZXIiOjE3MDQzNzI5NDd9LCJuYmYiOjE3MDQzNjkzNDAsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDptb25pdG9yaW5nOnByb21ldGhldXMtazhzIn0.FSnSMfUy_9HDtjROkDgqcsY1TL2TAtqtBui-uTrPai1jxJJ8MkJXreqeM57krXqugIqVbWDUhZiFCDtljnrbs67Xc1A5AJdvnxFxU73UF8uLLcGWeu0l3vORKZIyXtMLl9dz7c-w_j3bu74Qb0qnyY_OJeyKJTCQSSNhFhIQ8cr-3mQ91K8HGBB-H67HyE3exS24grCOt9UVLmmkbxJCFQ5_CnqLXZBu8b8-md6AmrHMARucm8digcYMAdanP-nNY7FftelOC2S7GCztBVA3Ur_ZaJiCgTe0WjRwUAHxW0Hxp9ZCLyZRilr8nJVgvit3LHqx_g0TDOKAAZ_XvHGhLg\"\n" +
                "        },\n" +
                "        \"status\": {\n" +
                "            \"authenticated\": true,\n" +
                "            \"user\": {\n" +
                "                \"username\": \"system:serviceaccount:monitoring:prometheus-k8s\",\n" +
                "                \"uid\": \"08017bfe-fc86-45a3-8686-066550852047\",\n" +
                "                \"groups\": [\n" +
                "                    \"system:serviceaccounts\",\n" +
                "                    \"system:serviceaccounts:monitoring\",\n" +
                "                    \"system:authenticated\"\n" +
                "                ],\n" +
                "                \"extra\": {\n" +
                "                    \"authentication.kubernetes.io/pod-name\": [\n" +
                "                        \"prometheus-k8s-0\"\n" +
                "                    ],\n" +
                "                    \"authentication.kubernetes.io/pod-uid\": [\n" +
                "                        \"2acb65ce-1ede-4c18-8a88-99daf27744eb\"\n" +
                "                    ]\n" +
                "                }\n" +
                "            },\n" +
                "            \"audiences\": [\n" +
                "                \"https://kubernetes.default.svc.cluster.local\"\n" +
                "            ]\n" +
                "        }\n" +
                "    },\n" +
                "    \"requestReceivedTimestamp\": \"2024-01-04T11:59:41.329438Z\",\n" +
                "    \"stageTimestamp\": \"2024-01-04T11:59:41.331244Z\",\n" +
                "    \"annotations\": {\n" +
                "        \"authorization.k8s.io/decision\": \"allow\",\n" +
                "        \"authorization.k8s.io/reason\": \"RBAC: allowed by ClusterRoleBinding \\\"resource-metrics:system:auth-delegator\\\" of ClusterRole \\\"system:auth-delegator\\\" to ServiceAccount \\\"prometheus-adapter/monitoring\\\"\"\n" +
                "    }\n" +
                "}";
        Event event = jsonStrToEvent(json);
        System.out.println(JSON.toJSONString(event));
    }
}

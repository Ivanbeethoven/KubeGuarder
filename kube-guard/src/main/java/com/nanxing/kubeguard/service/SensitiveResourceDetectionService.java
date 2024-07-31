package com.nanxing.kubeguard.service;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.github.wnameless.json.flattener.JsonFlattener;
import com.nanxing.kubeguard.component.mq.PacketSender;
import com.nanxing.kubeguard.entity.audit.Event;
import com.nanxing.kubeguard.entity.audit.ObjectRef;
import com.nanxing.kubeguard.entity.auth.*;
import com.nanxing.kubeguard.entity.keywordmatching.*;
import com.nanxing.kubeguard.listener.KubernetesContextFlushEvent;
import com.nanxing.kubeguard.utils.CommonUtils;
import com.nanxing.kubeguard.utils.RedisCache;
import io.kubernetes.client.openapi.models.V1Service;
import io.kubernetes.client.openapi.models.V1ServicePort;
import lombok.extern.slf4j.Slf4j;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.core.io.ClassPathResource;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.util.Base64Utils;
import org.springframework.util.CollectionUtils;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Author: Nanxing
 * Date: 2024/3/17 15:56
 */
//


@Service
@Slf4j
public class SensitiveResourceDetectionService {

    @Autowired
    private KubernetesContext kubernetesContext;

    private SensitiveResourceDetectionConfig sensitiveResourceDetectionConfig;

    private List<ServiceAccountAndIPs> supervisedServiceAccounts;

    //MyWebSocketClient wsClient;
    private WebSocketClient wsClient;

    @Autowired
    private PacketSender packetSender;


    @Autowired
    private RedisCache redisCache;

    @PostConstruct
    private void init(){
        initKeywordConfig();
        //initWSClient();
    }

    @PreDestroy
    private void destroy(){
        if(wsClient != null && wsClient.isOpen()){
            wsClient.close();
        }
    }

    private void initKeywordConfig(){
        ClassPathResource classPathResource = new ClassPathResource("keyword-config.json");
        if(!classPathResource.exists())
            return ;
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(classPathResource.getInputStream()));
            String json = reader.lines().collect(Collectors.joining("\n"));
            reader.close();
            this.sensitiveResourceDetectionConfig = JSONObject.parseObject(json, SensitiveResourceDetectionConfig.class);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    //private void initWSClient(){
    //    try {
    //        URI uri = new URI("ws://192.168.137.200:8899/api/wsFull");
    //        this.wsClient = new WebSocketClient(uri) {
    //            @Override
    //            public void onOpen(ServerHandshake serverHandshake) {
    //                log.info("Opened connection");
    //            }
    //
    //            @Override
    //            public void onMessage(String s) {
    //                log.info("Received message");
    //                preProcessPacket(s);
    //            }
    //
    //            @Override
    //            public void onClose(int i, String s, boolean b) {
    //                log.info("Websocket has been closed");
    //            }
    //
    //            @Override
    //            public void onError(Exception e) {
    //                e.printStackTrace();
    //            }
    //        };
    //        this.wsClient.connect();
    //    } catch (URISyntaxException e) {
    //        e.printStackTrace();
    //    }
    //}

    private void preProcessPacket(String packet){
        JSONObject jsonObject = null;
        try {
            jsonObject = JSONObject.parseObject(packet);
        } catch (Exception e) {
            log.warn("数据包无法转为JSON");
        }
        if(jsonObject == null){
            return;
        }
        packetSender.sendOrderMessage(jsonObject);
    }


    @EventListener(classes = {KubernetesContextFlushEvent.class})
    public void filterServiceAccounts(){
        //this.filteredServiceAccountSignatureSet = new HashSet<>();
        List<ServiceAccountAndIPs> filteredServiceAccounts = new ArrayList<>();
        Set<String> namespaceSet = new HashSet<>();
        if(CollectionUtils.isEmpty(kubernetesContext.serviceAccountList)){
            return;
        }
        for (ServiceAccount serviceAccount : kubernetesContext.serviceAccountList) {
            List<Role> roleList = serviceAccount.getRoleList();
            List<ClusterRole> clusterRoleList = serviceAccount.getClusterRoleList();
            List<Rule> roleRuleList = roleList
                    .stream()
                    .flatMap((Function<Role, Stream<Rule>>) role -> role.getRuleList().stream())
                    .collect(Collectors.toList());
            List<Rule> clusterRoleRuleList = clusterRoleList
                    .stream()
                    .flatMap((Function<ClusterRole, Stream<Rule>>) role -> role.getRuleList().stream())
                    .collect(Collectors.toList());


            for (ResourceKeywordConfig item : sensitiveResourceDetectionConfig.getItems()) {

                Optional<Rule> any1 = roleRuleList.stream()
                        .filter(rule -> CollectionUtils.isEmpty(rule.getNonResourceURLs()))
                        .filter(rule -> rule.getApiGroups().contains("*") || rule.getApiGroups().contains(item.getApiGroup()))
                        .filter(rule -> rule.getClasses().contains("*") || rule.getClasses().contains(item.getResource()))
                        .findAny();
                if(any1.isPresent()){ //说明该账户拥有敏感资源的访问权限
                    ServiceAccountAndIPs serviceAccountAndIPs = findIPsByServiceAccount(serviceAccount);
                    filteredServiceAccounts.add(serviceAccountAndIPs);
                    namespaceSet.add(serviceAccount.getNamespace());
                    break;
                }
                Optional<Rule> any2 = clusterRoleRuleList.stream()
                        .filter(rule -> CollectionUtils.isEmpty(rule.getNonResourceURLs()))
                        .filter(rule -> rule.getApiGroups().contains("*") || rule.getApiGroups().contains(item.getApiGroup()))
                        .filter(rule -> rule.getClasses().contains("*") || rule.getClasses().contains(item.getResource()))
                        .findAny();
                if(any2.isPresent()){ //说明该账户拥有敏感资源的访问权限
                    ServiceAccountAndIPs serviceAccountAndIPs = findIPsByServiceAccount(serviceAccount);
                    filteredServiceAccounts.add(serviceAccountAndIPs);
                    namespaceSet.add(serviceAccount.getNamespace());
                    break;
                }
            }
        }
        this.supervisedServiceAccounts = filteredServiceAccounts;
        log.info("Service accounts to be monitored have been filtered.");

        //在更新完服务账户列表后，需要进一步想WS端点发送消息，这里只根据命名空间过滤流量
        String message = "(response.status < 300) and (";
        StringBuilder sb = new StringBuilder();
        sb.append("(response.status < 300) and (dst.name == \"kubernetes\" or dst.name == \"kubelet\" or ");
        for (String ns : namespaceSet) {
            sb.append("src.namespace==\"");
            sb.append(ns);
            sb.append("\"");
            sb.append(" or ");
            sb.append("dst.namespace==\"");
            sb.append(ns);
            sb.append("\"");
            sb.append(" or ");
        }
        sb.delete(sb.length() - 4, sb.length());
        sb.append(")");
        try {
            URI uri = new URI("ws://192.168.137.200:8899/api/wsFull");
            WebSocketClient wsc = new WebSocketClient(uri) {
                @Override
                public void onOpen(ServerHandshake serverHandshake) {
                    log.info("Opened connection");
                    //send("request.path==\"/secrets/test-5\"");
                    send(sb.toString());
                    log.info("Sent KFL to Kubershark: [{}]", sb);
                }

                @Override
                public void onMessage(String s) {
                    //log.info("Received message");
                    preProcessPacket(s);
                }

                @Override
                public void onClose(int i, String s, boolean b) {
                    log.info("Websocket has been closed");
                }

                @Override
                public void onError(Exception e) {
                    e.printStackTrace();
                }
            };
            wsc.connect();

            if(this.wsClient != null && wsClient.isOpen()){
                wsClient.close();
            }
            wsClient = wsc;
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }


    private ServiceAccountAndIPs findIPsByServiceAccount(ServiceAccount serviceAccount){
        ServiceAccountAndIPs serviceAccountAndIPs = new ServiceAccountAndIPs();
        serviceAccountAndIPs.setNamespace(serviceAccount.getNamespace());
        serviceAccountAndIPs.setName(serviceAccount.getName());

        List<Pod> podList = serviceAccount.getPodList();
        //首先获取podIPs
        Set<String> podIPSet = podList.stream()
                .map(Pod::getIp)
                .collect(Collectors.toSet());

        serviceAccountAndIPs.setPodIPSet(podIPSet);
        serviceAccountAndIPs.setNodePortSet(new HashSet<>());
        serviceAccountAndIPs.setClusterServiceIPSet(new HashSet<>());

        for (Pod pod : podList) {

            String namespace = pod.getNamespace();
            Map<String, String> labels = pod.getLabels();
            if(labels == null){
                continue;
            }
            List<V1Service> filteredV1ServiceList = kubernetesContext.v1ServiceList.stream()
                    .filter(v1Service -> v1Service.getMetadata().getNamespace().equals(namespace))
                    .filter(v1Service -> {
                        Map<String, String> selector = v1Service.getSpec().getSelector();
                        for (String key : selector.keySet()) {
                            if (labels.containsKey(key) && labels.get(key).equals(selector.get(key))) {
                                return true;
                            }
                        }
                        return false;
                    }).collect(Collectors.toList());
            for (V1Service v1Service : filteredV1ServiceList) {
                String type = v1Service.getSpec().getType();
                if("NodePort".equals(type)){
                    Set<Integer> nodePortSet = v1Service
                            .getSpec()
                            .getPorts()
                            .stream()
                            .map(V1ServicePort::getNodePort).collect(Collectors.toSet());
                    serviceAccountAndIPs.getNodePortSet().addAll(nodePortSet);
                }

                String clusterIP = v1Service.getSpec().getClusterIP();
                serviceAccountAndIPs.getClusterServiceIPSet().add(clusterIP);
            }
        }
        return serviceAccountAndIPs;

    }

    //根据事件提取关键词，并存入Redis
    @Async
    public void extractKeywordsFromEvent(Event event){
        //首先先判断event的服务账户是否在被监控服务账户列表内
        String username = event.getUser().getUsername();

        if(!username.startsWith("system:serviceaccount:")){
            return ;
        }

        String[] split = username.split(":");
        String serviceNamespace = split[2];
        String serviceName = split[3];

        //如果服务账户不在监控范围内，则不进行提取
        boolean flag = this.supervisedServiceAccounts.stream().anyMatch(new Predicate<ServiceAccountAndIPs>() {
            @Override
            public boolean test(ServiceAccountAndIPs serviceAccountAndIPs) {
                return serviceNamespace.equals(serviceAccountAndIPs.getNamespace()) && serviceName.equals(serviceAccountAndIPs.getName());
            }
        });
        if(!flag){
            return;
        }

        //
        ObjectRef objectRef = event.getObjectRef();
        if(objectRef == null){
            return;
        }

        String resource = objectRef.getResource();
        String resourceApiGroup = objectRef.getApiGroup();
        if(resourceApiGroup == null){
            resourceApiGroup = "";
        }

        //判断访问的资源是否属于敏感资源
        String finalResourceApiGroup = resourceApiGroup;
        Optional<ResourceKeywordConfig> keywordConfigOptional = this.sensitiveResourceDetectionConfig.getItems().stream()
                .filter(resourceKeywordConfig -> resourceKeywordConfig.getApiGroup().equals(finalResourceApiGroup) &&
                        resourceKeywordConfig.getResource().equals(resource))
                .findFirst();
        if(!keywordConfigOptional.isPresent()){ //如果不属于敏感资源，则不提取直接返回
            return;
        }
        ResourceKeywordConfig resourceKeywordConfig = keywordConfigOptional.get();
        List<String> fields = resourceKeywordConfig.getFields();

        //从ResponseObject提取访问的资源对象
        JSONObject responseObject = event.getResponseObject();
        List<JSONObject> resourceList = parseResponseObject(responseObject);

        //提取关键词并加入Redis
        for (JSONObject jsonObject : resourceList) {

            //展平
            JSONObject flattenJson = flattenJson(jsonObject);

            Map<String, String> keywordMap = new HashMap<>();
            for (String pattern : fields) {
                for (String key : flattenJson.keySet()) {
                    if(CommonUtils.isMatch(key, pattern)){
                        String value = flattenJson.getString(key);
                        if(!"".equals(value))
                            keywordMap.put(key, flattenJson.getString(key));
                    }
                }
            }

            if(!keywordMap.isEmpty()){
                ResourceAndKeywords resourceAndKeywords = new ResourceAndKeywords();
                resourceAndKeywords.setResource(resource);
                resourceAndKeywords.setApiGroup(resourceApiGroup);
                if(flattenJson.containsKey("metadata.namespace")){
                    resourceAndKeywords.setNamespace(flattenJson.getString("metadata.namespace"));
                }
                if(flattenJson.containsKey("metadata.name")){
                    resourceAndKeywords.setName(flattenJson.getString("metadata.name"));
                }
                resourceAndKeywords.setKeywordMap(keywordMap);

                //加入Redis
                String redisKey = "resource-keywords:" + serviceNamespace + ":" + serviceName + ":" + resourceAndKeywords.getResourceSignature();
                redisCache.setCacheObject(redisKey, resourceAndKeywords, sensitiveResourceDetectionConfig.getExpireTime(), TimeUnit.SECONDS);
            }
        }
    }

    //处理Packet
    public SensitivityResourceLeakageDetectionReport processPacket(JSONObject packet){
        String srcIP = packet.getJSONObject("src").getString("ip");
        JSONObject dst = packet.getJSONObject("dst");
        String dstIP = dst.getString("ip");
        String dstPort = dst.getString("port");

        SensitivityResourceLeakageDetectionReport report = new SensitivityResourceLeakageDetectionReport();
        report.setPacket(packet);
        report.setLeakage(false);
        report.setSrcIp(srcIP);
        report.setDstIp(dstIP);

        //过滤代理流量
        if("10.244.0.0".equals(srcIP) || "10.244.1.1".equals(srcIP)){
            return report;
        }

        //找到srcIP对应的ServiceAccount
        Optional<ServiceAccountAndIPs> srcServiceAccountAndIPsOptional = supervisedServiceAccounts
                .stream()
                .filter(serviceAccountAndIPs -> serviceAccountAndIPs.getPodIPSet().contains(srcIP))
                .findAny();

        Optional<ServiceAccountAndIPs> dstServiceAccountAndIPsOptional = Optional.empty();
        //找到dstIP对应的ServiceAccount
        if(kubernetesContext.nodeIpList.contains(dstIP)){ //说明是打向NodePort或者DaemonSet的
            //首先判断是否是打向NodePort的
            dstServiceAccountAndIPsOptional = supervisedServiceAccounts.stream().filter(serviceAccountAndIPs -> {
                Set<Integer> nodePortSet = serviceAccountAndIPs.getNodePortSet();
                if (!nodePortSet.isEmpty() && nodePortSet.contains(Integer.valueOf(dstPort))) {
                    return true;
                }
                return false;
            }).findAny();
        }
        //如果不存在，则按照PodIP处理
        if(!dstServiceAccountAndIPsOptional.isPresent()){
            dstServiceAccountAndIPsOptional = supervisedServiceAccounts.stream().filter(serviceAccountAndIPs -> {
                return serviceAccountAndIPs.getPodIPSet().contains(dstIP);
            }).findAny();
        }

        //新加的
        if(srcServiceAccountAndIPsOptional.isPresent()){
            ServiceAccountAndIPs srcServiceAccountAndIPs = srcServiceAccountAndIPsOptional.get();
            String srcNamespace = srcServiceAccountAndIPs.getNamespace();
            String srcName = srcServiceAccountAndIPs.getName();
            report.setSrcAccount(srcNamespace + "/" + srcName);
        }
        if(dstServiceAccountAndIPsOptional.isPresent()){
            ServiceAccountAndIPs dstServiceAccountAndIPs = dstServiceAccountAndIPsOptional.get();
            String dstNamespace = dstServiceAccountAndIPs.getNamespace();
            String dstName = dstServiceAccountAndIPs.getName();
            report.setSrcAccount(dstNamespace + "/" + dstName);
        }


        //如果都存在，说明是集群内部的通信
        if(srcServiceAccountAndIPsOptional.isPresent() && dstServiceAccountAndIPsOptional.isPresent()){
            ServiceAccountAndIPs srcServiceAccountAndIPs = srcServiceAccountAndIPsOptional.get();
            ServiceAccountAndIPs dstServiceAccountAndIPs = dstServiceAccountAndIPsOptional.get();
            String srcNamespace = srcServiceAccountAndIPs.getNamespace();
            String srcName = srcServiceAccountAndIPs.getName();
            String dstNamespace = dstServiceAccountAndIPs.getNamespace();
            String dstName = dstServiceAccountAndIPs.getName();
            //如果是同一个服务账户，则无需进行检测
            if(srcNamespace.equals(dstNamespace) && srcName.equals(dstName)){
                return report;
            }

            //检测请求消息中是否包含srcServiceAccount的关键词
            JSONObject request = packet.getJSONObject("request");
            LeakageDetail requestLeakageDetail = this.matchKeywordForHTTP(request, srcNamespace, srcName);
            if(!requestLeakageDetail.getTargetedKeywords().isEmpty()){
                requestLeakageDetail.setDestIP(dstIP);
                report.setRequest(requestLeakageDetail);
                report.setLeakage(true);
            }

            //检测回复消息
            JSONObject response = packet.getJSONObject("response");
            LeakageDetail responseLeakageDetail = this.matchKeywordForHTTP(response, dstNamespace, dstName);
            if(!responseLeakageDetail.getTargetedKeywords().isEmpty()){
                responseLeakageDetail.setDestIP(srcIP);
                report.setResponse(responseLeakageDetail);
                report.setLeakage(true);
            }
            return report;
        }
        if(srcServiceAccountAndIPsOptional.isPresent()){
            ServiceAccountAndIPs srcServiceAccountAndIPs = srcServiceAccountAndIPsOptional.get();
            String srcNamespace = srcServiceAccountAndIPs.getNamespace();
            String srcName = srcServiceAccountAndIPs.getName();
            //检测请求消息中是否包含srcServiceAccount的关键词
            JSONObject request = packet.getJSONObject("request");
            LeakageDetail requestLeakageDetail = this.matchKeywordForHTTP(request, srcNamespace, srcName);
            if(!requestLeakageDetail.getTargetedKeywords().isEmpty()){
                requestLeakageDetail.setDestIP(dstIP);
                report.setRequest(requestLeakageDetail);
                report.setLeakage(true);
            }
            return report;
        }
        if(dstServiceAccountAndIPsOptional.isPresent()){
            ServiceAccountAndIPs dstServiceAccountAndIPs = dstServiceAccountAndIPsOptional.get();
            String dstNamespace = dstServiceAccountAndIPs.getNamespace();
            String dstName = dstServiceAccountAndIPs.getName();

            //检测回复消息
            JSONObject response = packet.getJSONObject("response");
            LeakageDetail responseLeakageDetail = this.matchKeywordForHTTP(response, dstNamespace, dstName);
            if(!responseLeakageDetail.getTargetedKeywords().isEmpty()){
                responseLeakageDetail.setDestIP(srcIP);
                report.setResponse(responseLeakageDetail);
                report.setLeakage(true);
            }
        }
        return report;

    }

    //匹配关键词
    //String redisKey = "resource-keywords:" + serviceNamespace + ":" + serviceName + ":" + resourceAndKeywords.getResourceSignature();
    private LeakageDetail matchKeywordForHTTP(JSONObject entity, String serviceAccountNamespace, String serviceAccountName){
        String prefix = "resource-keywords:" + serviceAccountNamespace + ":" + serviceAccountName;
        Collection<String> keys = redisCache.keys(prefix + ":*");
        List<ResourceAndKeywords> resourceAndKeywordsList = new ArrayList<>();
        for (String key : keys) {
            try {
                ResourceAndKeywords resourceAndKeywords = redisCache.getCacheObject(key);
                resourceAndKeywordsList.add(resourceAndKeywords);
            } catch (Exception e) {
                System.out.println("数据已经过期.");
            }
        }

        LeakageDetail leakageDetail = new LeakageDetail();
        leakageDetail.setServiceAccountName(serviceAccountName);
        leakageDetail.setServiceAccountNamespace(serviceAccountNamespace);
        List<ResourceAndKeywords> targetedKeywords = new ArrayList<>();
        leakageDetail.setTargetedKeywords(targetedKeywords);

        //匹配headers
        if(entity.containsKey("headers")){
            JSONObject headers = entity.getJSONObject("headers");
            String[] outerHeaders = new String[]{"Accept", "Accept-Encoding", "Cache-Control", "Host", "Postman-Token", "User-Agent", "Content-Length", "Content-Type", "Date"};
            Set<String> outerSet = new HashSet<>(Arrays.asList(outerHeaders));
            Set<String> headerKeySet = headers.keySet()
                    .stream()
                    .filter(s -> !outerSet.contains(s))
                    .collect(Collectors.toSet());
            for (String headerKey : headerKeySet) {
                String headerValue = headers.getString(headerKey);
                List<ResourceAndKeywords> filteredResourceAndKeywordList =
                        this.matchKeywordForText(headerValue, resourceAndKeywordsList);
                targetedKeywords.addAll(filteredResourceAndKeywordList);
            }
        }
        if(entity.containsKey("cookies")){
            JSONObject cookies = entity.getJSONObject("cookies");
            if(!cookies.isEmpty()){
                String cookieStr = cookies.toJSONString();
                List<ResourceAndKeywords> filteredResourceAndKeywordList =
                        this.matchKeywordForText(cookieStr, resourceAndKeywordsList);
                targetedKeywords.addAll(filteredResourceAndKeywordList);
            }
        }
        if(entity.containsKey("content")){
            JSONObject content = entity.getJSONObject("content");
            if(content.containsKey("text")){
                String textStr = content.getString("text");

                //如果是Base64编码，先将其解码
                if(content.containsKey("encoding") && "base64".equals(content.getString("encoding"))){
                    byte[] bytes = Base64Utils.decodeFromString(textStr);
                    textStr = new String(bytes);
                }
                List<ResourceAndKeywords> filteredResourceAndKeywordList =
                        this.matchKeywordForText(textStr, resourceAndKeywordsList);
                targetedKeywords.addAll(filteredResourceAndKeywordList);
            }
        }
        return leakageDetail;
    }




    private List<ResourceAndKeywords> matchKeywordForText(String text, List<ResourceAndKeywords> resourceAndKeywordsList){
        List<ResourceAndKeywords> filteredResourceAndKeywordsList = new ArrayList<>();
        for (ResourceAndKeywords resourceAndKeywords : resourceAndKeywordsList) {
            Set<Map.Entry<String, String>> entrySet = resourceAndKeywords.getKeywordMap().entrySet();
            Set<Map.Entry<String, String>> filteredEntrySet = entrySet.stream()
                    .filter(stringStringEntry -> {
                        String value = stringStringEntry.getValue();
                        return text.contains(value);
                    })
                    .collect(Collectors.toSet());
            //如果不为空，说明有关键词命中
            if(!filteredEntrySet.isEmpty()){
                ResourceAndKeywords newResourceAndKeywords = new ResourceAndKeywords();
                newResourceAndKeywords.setResource(resourceAndKeywords.getResource());
                newResourceAndKeywords.setNamespace(resourceAndKeywords.getNamespace());
                newResourceAndKeywords.setName(resourceAndKeywords.getName());
                newResourceAndKeywords.setApiGroup(resourceAndKeywords.getApiGroup());
                Map<String, String> newKeywordMap = new HashMap<>();
                for (Map.Entry<String, String> stringStringEntry : filteredEntrySet) {
                    newKeywordMap.put(stringStringEntry.getKey(), stringStringEntry.getValue());
                }
                newResourceAndKeywords.setKeywordMap(newKeywordMap);
                filteredResourceAndKeywordsList.add(newResourceAndKeywords);
            }
        }
        return filteredResourceAndKeywordsList;
    }


    //从event的responseObject字段解析访问到的资源列表
    private List<JSONObject> parseResponseObject(JSONObject jsonObject){
        List<JSONObject> resourceList = new ArrayList<>();
        if(jsonObject == null || !jsonObject.containsKey("kind")){ //如果没有该字段，说明没有返回资源对象
            return resourceList;
        }
        String kind = jsonObject.getString("kind");
        String apiVersion = jsonObject.getString("apiVersion");
        if(kind.endsWith("List")){ //说明返回的是一个列表
            String newKind = kind.substring(0, kind.length() - 4);
            if(!jsonObject.containsKey("items")){
                return resourceList;
            }
            JSONArray jsonArray = jsonObject.getJSONArray("items");
            for (int i = 0; i < jsonArray.size(); i++) {
                JSONObject item = jsonArray.getJSONObject(i);
                item.put("kind", newKind);
                item.put("apiVersion", apiVersion);
                resourceList.add(item);
            }
        }else{//如果返回的不是一个列表，则直接加入
            resourceList.add(jsonObject);
        }
        return resourceList;
    }


    //以下两个方法用于将一个JSONObject展平
    private JSONObject flattenJson(JSONObject jsonObject) {
        String json = jsonObject.toJSONString();
        String flatten = JsonFlattener.flatten(json);
        return JSONObject.parseObject(flatten);
    }



    public static void main(String[] args) {
        String jsonStr = "{\n" +
                "    \"kind\": \"SecretList\",\n" +
                "    \"apiVersion\": \"v1\",\n" +
                "    \"metadata\": {\n" +
                "        \"resourceVersion\": \"1423365\"\n" +
                "    },\n" +
                "    \"items\": [\n" +
                "        {\n" +
                "            \"metadata\": {\n" +
                "                \"name\": \"test-sa-secret\",\n" +
                "                \"namespace\": \"test\",\n" +
                "                \"uid\": \"26ea8967-2773-445c-a0d6-3cda12d90125\",\n" +
                "                \"resourceVersion\": \"1298860\",\n" +
                "                \"creationTimestamp\": \"2024-03-06T02:52:32Z\",\n" +
                "                \"labels\": {\n" +
                "                    \"kubernetes.io/legacy-token-last-used\": \"2024-03-17\"\n" +
                "                },\n" +
                "                \"annotations\": {\n" +
                "                    \"kubectl.kubernetes.io/last-applied-configuration\": \"{\\\"apiVersion\\\":\\\"v1\\\",\\\"kind\\\":\\\"Secret\\\",\\\"metadata\\\":{\\\"annotations\\\":{\\\"kubernetes.io/service-account.name\\\":\\\"test-sa\\\"},\\\"name\\\":\\\"test-sa-secret\\\",\\\"namespace\\\":\\\"test\\\"},\\\"type\\\":\\\"kubernetes.io/service-account-token\\\"}\\n\",\n" +
                "                    \"kubernetes.io/service-account.name\": \"test-sa\",\n" +
                "                    \"kubernetes.io/service-account.uid\": \"f1dabe5c-407d-46c7-a043-05c3dce52eb7\"\n" +
                "                },\n" +
                "                \"managedFields\": [\n" +
                "                    {\n" +
                "                        \"manager\": \"kube-controller-manager\",\n" +
                "                        \"operation\": \"Update\",\n" +
                "                        \"apiVersion\": \"v1\",\n" +
                "                        \"time\": \"2024-03-06T02:52:32Z\",\n" +
                "                        \"fieldsType\": \"FieldsV1\",\n" +
                "                        \"fieldsV1\": {\n" +
                "                            \"f:data\": {\n" +
                "                                \".\": {},\n" +
                "                                \"f:ca.crt\": {},\n" +
                "                                \"f:namespace\": {},\n" +
                "                                \"f:token\": {}\n" +
                "                            },\n" +
                "                            \"f:metadata\": {\n" +
                "                                \"f:annotations\": {\n" +
                "                                    \"f:kubernetes.io/service-account.uid\": {}\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    },\n" +
                "                    {\n" +
                "                        \"manager\": \"kubectl-client-side-apply\",\n" +
                "                        \"operation\": \"Update\",\n" +
                "                        \"apiVersion\": \"v1\",\n" +
                "                        \"time\": \"2024-03-06T02:52:32Z\",\n" +
                "                        \"fieldsType\": \"FieldsV1\",\n" +
                "                        \"fieldsV1\": {\n" +
                "                            \"f:metadata\": {\n" +
                "                                \"f:annotations\": {\n" +
                "                                    \".\": {},\n" +
                "                                    \"f:kubectl.kubernetes.io/last-applied-configuration\": {},\n" +
                "                                    \"f:kubernetes.io/service-account.name\": {}\n" +
                "                                }\n" +
                "                            },\n" +
                "                            \"f:type\": {}\n" +
                "                        }\n" +
                "                    },\n" +
                "                    {\n" +
                "                        \"manager\": \"kube-apiserver\",\n" +
                "                        \"operation\": \"Update\",\n" +
                "                        \"apiVersion\": \"v1\",\n" +
                "                        \"time\": \"2024-03-17T07:13:14Z\",\n" +
                "                        \"fieldsType\": \"FieldsV1\",\n" +
                "                        \"fieldsV1\": {\n" +
                "                            \"f:metadata\": {\n" +
                "                                \"f:labels\": {\n" +
                "                                    \".\": {},\n" +
                "                                    \"f:kubernetes.io/legacy-token-last-used\": {}\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                ]\n" +
                "            },\n" +
                "            \"data\": {\n" +
                "                \"ca.crt\": \"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCVENDQWUyZ0F3SUJBZ0lJU2FUOGJtWTkyNFF3RFFZSktvWklodmNOQVFFTEJRQXdGVEVUTUJFR0ExVUUKQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB5TkRBek1EUXdOVFV5TlROYUZ3MHpOREF6TURJd05UVTNOVE5hTUJVeApFekFSQmdOVkJBTVRDbXQxWW1WeWJtVjBaWE13Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLCkFvSUJBUUN3QUZieVVwVFpzYjdleUM0SE5vK1BPRWIrcW8zVWlzRzdyNk1ma3lXYmQ3dTE1U241TlBIN09UUVcKUFV2ZWQyWmpxczlPUWc1VG40VTM2VThyWEhXL2txU0JtMXVnbUR1TzVrWWRjbWwxekhtMkM0d0VJVGk2aHpFQQpHUEV5bHRsOFBLdk1PZkNnRnducTVWVHpORm5TRmtYTStwZmN6VElXNGxIa2plaE5DbDN2NURMZDJ4K2Y4L0hkCjgrVnZFN0NjeUZmT25Kci9UamE2c2ZKUnBzMDYycDRPYzEzWG5Xa2hXcjJrZVc1K0g0V0FlaE8rWVVLcHhTWXYKSGFWcmN0VVdKVjI2dU05VW1pWDROUUZPaXYwZjNrYkxNdmU4ZGFoY3d3WUlxY2I2a2NRdWJ3V2JsNGt2RndjdQpjaml6OFJSREJwQzRGcHM4RmYrUm1CK1lXS3lmQWdNQkFBR2pXVEJYTUE0R0ExVWREd0VCL3dRRUF3SUNwREFQCkJnTlZIUk1CQWY4RUJUQURBUUgvTUIwR0ExVWREZ1FXQkJRanpIcmpwUzdCMm10NmZLZTE5TVJYMmdQUnpUQVYKQmdOVkhSRUVEakFNZ2dwcmRXSmxjbTVsZEdWek1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQkFRQlZwcHdZS21EcQpQdktvQ3pFQlRUTVBIZnBQMVg1SVZmWVFMcXRyd1BXWUl4UU5hbVBudlFuZnpFWjNKWk1nZERpZ2YvK1hrZy84CkdZK2k4UGl4cnExZStRbDh2UDFTT3F1NllGRzRyR3ZibUJ3VU5USnltOHI4Mk5qOFdSTTdiaURLenN5VXVXVEYKakYvWWoxU0pzTFRINTdKM3IyVUtKSm54VHJWMXZBUWVXU3lkYWRlSGNGdStzRk1qNGpQUzZ4Tkxxb3ZuM2pGUgp5SDlUR3NWNTN5ZDdBL0xFTy9BR2tscmo3ZW1QMno3WTRzSng2ajNEb2FYR2NzNFVkdXhza0svenFVdWZwaENaCkVUME5NQjZ3azVrZ0xFUjRyQ1JEeWRsbmlBMTZ0bzJiazJZTDFzL3RPY0FvdkVpKzNKc1dTVzVTbDVyV3BCeGMKZGZMbUNsRHU1NWp1Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K\",\n" +
                "                \"namespace\": \"dGVzdA==\",\n" +
                "                \"token\": \"ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbXRwWkNJNklrc3hPRVZ0V1hGM1l6Sm9YMHRyV0VRd1prRTBYMjlhVjNSaWFrWTNWblZ4VlRobFl6TlVRakJrTjFFaWZRLmV5SnBjM01pT2lKcmRXSmxjbTVsZEdWekwzTmxjblpwWTJWaFkyTnZkVzUwSWl3aWEzVmlaWEp1WlhSbGN5NXBieTl6WlhKMmFXTmxZV05qYjNWdWRDOXVZVzFsYzNCaFkyVWlPaUowWlhOMElpd2lhM1ZpWlhKdVpYUmxjeTVwYnk5elpYSjJhV05sWVdOamIzVnVkQzl6WldOeVpYUXVibUZ0WlNJNkluUmxjM1F0YzJFdGMyVmpjbVYwSWl3aWEzVmlaWEp1WlhSbGN5NXBieTl6WlhKMmFXTmxZV05qYjNWdWRDOXpaWEoyYVdObExXRmpZMjkxYm5RdWJtRnRaU0k2SW5SbGMzUXRjMkVpTENKcmRXSmxjbTVsZEdWekxtbHZMM05sY25acFkyVmhZMk52ZFc1MEwzTmxjblpwWTJVdFlXTmpiM1Z1ZEM1MWFXUWlPaUptTVdSaFltVTFZeTAwTURka0xUUTJZemN0WVRBME15MHdOV016WkdObE5USmxZamNpTENKemRXSWlPaUp6ZVhOMFpXMDZjMlZ5ZG1salpXRmpZMjkxYm5RNmRHVnpkRHAwWlhOMExYTmhJbjAuV1U1WVc2SWplMlhWalh1bHlkZko0bkJqM3RocGMtSlBpcVJpY01TTU5sYW5QS2FxSHBQc01mY1RBWnI3ODFkQlVBVmJUSnVvRGZodVhsWWpjOElMRF9nd0pvd1ZrOVF1YktUSEJYeEZ1bGZ2UHlDQkV2emRvd3lpaDB3alE4N0RIc2tNWU42ZXpmeEVNZUtoWDA4RjVCaHNWdVhwWk5MTGdrZ2JMcTgycDlxQWhjTlFYdlF2WnprU1hxcWhnR1RXVGJIblN5WjlGbjZMUDByd3UwZFlFM2hob3ZOMjVMYUhaM3ZkLVVIblhaNW5hZnNXaDl1Umg1Vlp1Vk5kMXdHYkIyblNGUFZuay0xaHFfWkpqTy0xZVFrU2dYUUt2TGg3TzBjOFBNNVZWYTBxU3Y5M1ptY25HRGJrbnV1NE5BcF8teEdYSVBEZHlYQTJ6WDAwbDd0bEt3\"\n" +
                "            },\n" +
                "            \"type\": \"kubernetes.io/service-account-token\"\n" +
                "        }\n" +
                "    ]\n" +
                "}";
        //JSONObject jsonObject = JSONObject.parseObject(jsonStr);
        //
        //String items = jsonObject.getString("items");
        //System.out.println(items);
        //JSONObject flattenJson = new SensitiveResourceDetectionService().flattenJson(jsonObject);
        //System.out.println(JSONObject.toJSONString(flattenJson, SerializerFeature.PrettyFormat));
        String textStr = "eyJhcGlWZXJzaW9uIjoidjEiLCJpdGVtcyI6W3sibWV0YWRhdGEiOnsiYW5ub3RhdGlvbnMiOnt9LCJjcmVhdGlvblRpbWVzdGFtcCI6IjIwMjQtMDMtMTZUMDk6NTc6MzkuMDAwMDAwWiIsImdlbmVyYXRlTmFtZSI6Imt1YmVzaGFyay1mcm9udC05OWNjNjc4ZDQtIiwibGFiZWxzIjp7ImFwcC5rdWJlcm5ldGVzLmlvL2luc3RhbmNlIjoia3ViZXNoYXJrIiwiYXBwLmt1YmVybmV0ZXMuaW8vbWFuYWdlZC1ieSI6IkhlbG0iLCJhcHAua3ViZXJuZXRlcy5pby9uYW1lIjoia3ViZXNoYXJrIiwiYXBwLmt1YmVybmV0ZXMuaW8vdmVyc2lvbiI6IjUyLjEuNzUiLCJhcHAua3ViZXNoYXJrLmNvL2FwcCI6ImZyb250IiwiaGVsbS5zaC9jaGFydCI6Imt1YmVzaGFyay01Mi4xLjc1IiwicG9kLXRlbXBsYXRlLWhhc2giOiI5OWNjNjc4ZDQifSwibWFuYWdlZEZpZWxkcyI6W3siYXBpVmVyc2lvbiI6InYxIiwiZmllbGRzVHlwZSI6IkZpZWxkc1YxIiwiZmllbGRzVjEiOnsiZjptZXRhZGF0YSI6eyJmOmdlbmVyYXRlTmFtZSI6e30sImY6bGFiZWxzIjp7Ii4iOnt9LCJmOmFwcC5rdWJlcm5ldGVzLmlvL2luc3RhbmNlIjp7fSwiZjphcHAua3ViZXJuZXRlcy5pby9tYW5hZ2VkLWJ5Ijp7fSwiZjphcHAua3ViZXJuZXRlcy5pby9uYW1lIjp7fSwiZjphcHAua3ViZXJuZXRlcy5pby92ZXJzaW9uIjp7fSwiZjphcHAua3ViZXNoYXJrLmNvL2FwcCI6e30sImY6aGVsbS5zaC9jaGFydCI6e30sImY6cG9kLXRlbXBsYXRlLWhhc2giOnt9fSwiZjpvd25lclJlZmVyZW5jZXMiOnsiLiI6e30sIms6e1widWlkXCI6XCJiZWRiZmI0MS04MTZmLTQyZjEtOGFjYy03MmM1YmE4ZGRiN2FcIn0iOnt9fX0sImY6c3BlYyI6eyJmOmNvbnRhaW5lcnMiOnsiazp7XCJuYW1lXCI6XCJrdWJlc2hhcmstZnJvbnRcIn0iOnsiLiI6e30sImY6ZW52Ijp7Ii4iOnt9LCJrOntcIm5hbWVcIjpcIlJFQUNUX0FQUF9BVVRIX0VOQUJMRURcIn0iOnsiLiI6e30sImY6bmFtZSI6e30sImY6dmFsdWUiOnt9fSwiazp7XCJuYW1lXCI6XCJSRUFDVF9BUFBfQVVUSF9TQU1MX0lEUF9NRVRBREFUQV9VUkxcIn0iOnsiLiI6e30sImY6bmFtZSI6e30sImY6dmFsdWUiOnt9fSwiazp7XCJuYW1lXCI6XCJSRUFDVF9BUFBfQVVUSF9UWVBFXCJ9Ijp7Ii4iOnt9LCJmOm5hbWUiOnt9LCJmOnZhbHVlIjp7fX0sIms6e1wibmFtZVwiOlwiUkVBQ1RfQVBQX0RFRkFVTFRfRklMVEVSXCJ9Ijp7Ii4iOnt9LCJmOm5hbWUiOnt9LCJmOnZhbHVlIjp7fX0sIms6e1wibmFtZVwiOlwiUkVBQ1RfQVBQX1JFQ09SRElOR19ESVNBQkxFRFwifSI6eyIuIjp7fSwiZjpuYW1lIjp7fSwiZjp2YWx1ZSI6e319LCJrOntcIm5hbWVcIjpcIlJFQUNUX0FQUF9SRVBMQVlfRElTQUJMRURcIn0iOnsiLiI6e30sImY6bmFtZSI6e30sImY6dmFsdWUiOnt9fSwiazp7XCJuYW1lXCI6XCJSRUFDVF9BUFBfU0NSSVBUSU5HX0RJU0FCTEVEXCJ9Ijp7Ii4iOnt9LCJmOm5hbWUiOnt9LCJmOnZhbHVlIjp7fX0sIms6e1wibmFtZVwiOlwiUkVBQ1RfQVBQX1RBUkdFVEVEX1BPRFNfVVBEQVRFX0RJU0FCTEVEXCJ9Ijp7Ii4iOnt9LCJmOm5hbWUiOnt9LCJmOnZhbHVlIjp7fX19LCJmOmltYWdlIjp7fSwiZjppbWFnZVB1bGxQb2xpY3kiOnt9LCJmOmxpdmVuZXNzUHJvYmUiOnsiLiI6e30sImY6ZmFpbHVyZVRocmVzaG9sZCI6e30sImY6aW5pdGlhbERlbGF5U2Vjb25kcyI6e30sImY6cGVyaW9kU2Vjb25kcyI6e30sImY6c3VjY2Vzc1RocmVzaG9sZCI6e30sImY6dGNwU29ja2V0Ijp7Ii4iOnt9LCJmOnBvcnQiOnt9fSwiZjp0aW1lb3V0U2Vjb25kcyI6e319LCJmOm5hbWUiOnt9LCJmOnJlYWRpbmVzc1Byb2JlIjp7Ii4iOnt9LCJmOmZhaWx1cmVUaHJlc2hvbGQiOnt9LCJmOmluaXRpYWxEZWxheVNlY29uZHMiOnt9LCJmOnBlcmlvZFNlY29uZHMiOnt9LCJmOnN1Y2Nlc3NUaHJlc2hvbGQiOnt9LCJmOnRjcFNvY2tldCI6eyIuIjp7fSwiZjpwb3J0Ijp7fX0sImY6dGltZW91dFNlY29uZHMiOnt9fSwiZjpyZXNvdXJjZXMiOnsiLiI6e30sImY6bGltaXRzIjp7Ii4iOnt9LCJmOmNwdSI6e30sImY6bWVtb3J5Ijp7fX0sImY6cmVxdWVzdHMiOnsiLiI6e30sImY6Y3B1Ijp7fSwiZjptZW1vcnkiOnt9fX0sImY6dGVybWluYXRpb25NZXNzYWdlUGF0aCI6e30sImY6dGVybWluYXRpb25NZXNzYWdlUG9saWN5Ijp7fSwiZjp2b2x1bWVNb3VudHMiOnsiLiI6e30sIms6e1wibW91bnRQYXRoXCI6XCIvZXRjL25naW54L2NvbmYuZC9kZWZhdWx0LmNvbmZcIn0iOnsiLiI6e30sImY6bW91bnRQYXRoIjp7fSwiZjpuYW1lIjp7fSwiZjpyZWFkT25seSI6e30sImY6c3ViUGF0aCI6e319fX19LCJmOmRuc1BvbGljeSI6e30sImY6ZW5hYmxlU2VydmljZUxpbmtzIjp7fSwiZjpyZXN0YXJ0UG9saWN5Ijp7fSwiZjpzY2hlZHVsZXJOYW1lIjp7fSwiZjpzZWN1cml0eUNvbnRleHQiOnt9LCJmOnNlcnZpY2VBY2NvdW50Ijp7fSwiZjpzZXJ2aWNlQWNjb3VudE5hbWUiOnt9LCJmOnRlcm1pbmF0aW9uR3JhY2VQZXJpb2RTZWNvbmRzIjp7fSwiZjp2b2x1bWVzIjp7Ii4iOnt9LCJrOntcIm5hbWVcIjpcIm5naW54LWNvbmZpZ1wifSI6eyIuIjp7fSwiZjpjb25maWdNYXAiOnsiLiI6e30sImY6ZGVmYXVsdE1vZGUiOnt9LCJmOm5hbWUiOnt9fSwiZjpuYW1lIjp7fX19fX0sIm1hbmFnZXIiOiJrdWJlLWNvbnRyb2xsZXItbWFuYWdlciIsIm9wZXJhdGlvbiI6IlVwZGF0ZSIsInRpbWUiOiIyMDI0LTAzLTE2VDA5OjU3OjM5LjAwMDAwMFoifSx7ImFwaVZlcnNpb24iOiJ2MSIsImZpZWxkc1R5cGUiOiJGaWVsZHNWMSIsImZpZWxkc1YxIjp7ImY6c3RhdHVzIjp7ImY6Y29uZGl0aW9ucyI6eyJrOntcInR5cGVcIjpcIkNvbnRhaW5lcnNSZWFkeVwifSI6eyIuIjp7fSwiZjpsYXN0UHJvYmVUaW1lIjp7fSwiZjpsYXN0VHJhbnNpdGlvblRpbWUiOnt9LCJmOnN0YXR1cyI6e30sImY6dHlwZSI6e319LCJrOntcInR5cGVcIjpcIkluaXRpYWxpemVkXCJ9Ijp7Ii4iOnt9LCJmOmxhc3RQcm9iZVRpbWUiOnt9LCJmOmxhc3RUcmFuc2l0aW9uVGltZSI6e30sImY6c3RhdHVzIjp7fSwiZjp0eXBlIjp7fX0sIms6e1widHlwZVwiOlwiUmVhZHlcIn0iOnsiLiI6e30sImY6bGFzdFByb2JlVGltZSI6e30sImY6bGFzdFRyYW5zaXRpb25UaW1lIjp7fSwiZjpzdGF0dXMiOnt9LCJmOnR5cGUiOnt9fX0sImY6Y29udGFpbmVyU3RhdHVzZXMiOnt9LCJmOmhvc3RJUCI6e30sImY6cGhhc2UiOnt9LCJmOnBvZElQIjp7fSwiZjpwb2RJUHMiOnsiLiI6e30sIms6e1wiaXBcIjpcIjEwLjI0NC4xLjU4XCJ9Ijp7Ii4iOnt9LCJmOmlwIjp7fX19LCJmOnN0YXJ0VGltZSI6e319fSwibWFuYWdlciI6Imt1YmVsZXQiLCJvcGVyYXRpb24iOiJVcGRhdGUiLCJzdWJyZXNvdXJjZSI6InN0YXR1cyIsInRpbWUiOiIyMDI0LTAzLTIyVDA1OjQ2OjA2LjAwMDAwMFoifV0sIm5hbWUiOiJrdWJlc2hhcmstZnJvbnQtOTljYzY3OGQ0LXdxd3M0IiwibmFtZXNwYWNlIjoiZGVmYXVsdCIsIm93bmVyUmVmZXJlbmNlcyI6W3siYXBpVmVyc2lvbiI6ImFwcHMvdjEiLCJibG9ja093bmVyRGVsZXRpb24iOnRydWUsImNvbnRyb2xsZXIiOnRydWUsImtpbmQiOiJSZXBsaWNhU2V0IiwibmFtZSI6Imt1YmVzaGFyay1mcm9udC05OWNjNjc4ZDQiLCJ1aWQiOiJiZWRiZmI0MS04MTZmLTQyZjEtOGFjYy03MmM1YmE4ZGRiN2EifV0sInJlc291cmNlVmVyc2lvbiI6IjE4MDg3MjgiLCJ1aWQiOiI1YWY2ZTI4Zi1iMzIyLTQyOTYtOWI0MC0wYTFkMTI0MGE4ZTgifSwic3BlYyI6eyJjb250YWluZXJzIjpbeyJlbnYiOlt7Im5hbWUiOiJSRUFDVF9BUFBfREVGQVVMVF9GSUxURVIiLCJ2YWx1ZSI6IiAifSx7Im5hbWUiOiJSRUFDVF9BUFBfQVVUSF9FTkFCTEVEIiwidmFsdWUiOiJmYWxzZSJ9LHsibmFtZSI6IlJFQUNUX0FQUF9BVVRIX1RZUEUiLCJ2YWx1ZSI6InNhbWwifSx7Im5hbWUiOiJSRUFDVF9BUFBfQVVUSF9TQU1MX0lEUF9NRVRBREFUQV9VUkwiLCJ2YWx1ZSI6IiAifSx7Im5hbWUiOiJSRUFDVF9BUFBfUkVQTEFZX0RJU0FCTEVEIiwidmFsdWUiOiJmYWxzZSJ9LHsibmFtZSI6IlJFQUNUX0FQUF9TQ1JJUFRJTkdfRElTQUJMRUQiLCJ2YWx1ZSI6ImZhbHNlIn0seyJuYW1lIjoiUkVBQ1RfQVBQX1RBUkdFVEVEX1BPRFNfVVBEQVRFX0RJU0FCTEVEIiwidmFsdWUiOiJmYWxzZSJ9LHsibmFtZSI6IlJFQUNUX0FQUF9SRUNPUkRJTkdfRElTQUJMRUQiLCJ2YWx1ZSI6ImZhbHNlIn1dLCJpbWFnZSI6ImRvY2tlci5pby9rdWJlc2hhcmsvZnJvbnQ6djUyLjEuNzUiLCJpbWFnZVB1bGxQb2xpY3kiOiJBbHdheXMiLCJsaXZlbmVzc1Byb2JlIjp7ImZhaWx1cmVUaHJlc2hvbGQiOjMsImluaXRpYWxEZWxheVNlY29uZHMiOjMsInBlcmlvZFNlY29uZHMiOjEsInN1Y2Nlc3NUaHJlc2hvbGQiOjEsInRjcFNvY2tldCI6eyJwb3J0Ijo4MDgwfSwidGltZW91dFNlY29uZHMiOjF9LCJuYW1lIjoia3ViZXNoYXJrLWZyb250IiwicmVhZGluZXNzUHJvYmUiOnsiZmFpbHVyZVRocmVzaG9sZCI6MywiaW5pdGlhbERlbGF5U2Vjb25kcyI6MywicGVyaW9kU2Vjb25kcyI6MSwic3VjY2Vzc1RocmVzaG9sZCI6MSwidGNwU29ja2V0Ijp7InBvcnQiOjgwODB9LCJ0aW1lb3V0U2Vjb25kcyI6MX0sInJlc291cmNlcyI6eyJsaW1pdHMiOnsiY3B1IjoiNzUwbSIsIm1lbW9yeSI6IjFHaSJ9LCJyZXF1ZXN0cyI6eyJjcHUiOiI1MG0iLCJtZW1vcnkiOiI1ME1pIn19LCJ0ZXJtaW5hdGlvbk1lc3NhZ2VQYXRoIjoiL2Rldi90ZXJtaW5hdGlvbi1sb2ciLCJ0ZXJtaW5hdGlvbk1lc3NhZ2VQb2xpY3kiOiJGaWxlIiwidm9sdW1lTW91bnRzIjpbeyJtb3VudFBhdGgiOiIvZXRjL25naW54L2NvbmYuZC9kZWZhdWx0LmNvbmYiLCJuYW1lIjoibmdpbngtY29uZmlnIiwicmVhZE9ubHkiOnRydWUsInN1YlBhdGgiOiJkZWZhdWx0LmNvbmYifSx7Im1vdW50UGF0aCI6Ii92YXIvcnVuL3NlY3JldHMva3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudCIsIm5hbWUiOiJrdWJlLWFwaS1hY2Nlc3MtemZoNnQiLCJyZWFkT25seSI6dHJ1ZX1dfV0sImRuc1BvbGljeSI6IkNsdXN0ZXJGaXJzdFdpdGhIb3N0TmV0IiwiZW5hYmxlU2VydmljZUxpbmtzIjp0cnVlLCJub2RlTmFtZSI6Im5vZGUtMSIsIm5vZGVTZWxlY3RvciI6e30sIm92ZXJoZWFkIjp7fSwicHJlZW1wdGlvblBvbGljeSI6IlByZWVtcHRMb3dlclByaW9yaXR5IiwicHJpb3JpdHkiOjAsInJlc3RhcnRQb2xpY3kiOiJBbHdheXMiLCJzY2hlZHVsZXJOYW1lIjoiZGVmYXVsdC1zY2hlZHVsZXIiLCJzZWN1cml0eUNvbnRleHQiOnt9LCJzZXJ2aWNlQWNjb3VudCI6Imt1YmVzaGFyay1zZXJ2aWNlLWFjY291bnQiLCJzZXJ2aWNlQWNjb3VudE5hbWUiOiJrdWJlc2hhcmstc2VydmljZS1hY2NvdW50IiwidGVybWluYXRpb25HcmFjZVBlcmlvZFNlY29uZHMiOjMwLCJ0b2xlcmF0aW9ucyI6W3siZWZmZWN0IjoiTm9FeGVjdXRlIiwia2V5Ijoibm9kZS5rdWJlcm5ldGVzLmlvL25vdC1yZWFkeSIsIm9wZXJhdG9yIjoiRXhpc3RzIiwidG9sZXJhdGlvblNlY29uZHMiOjMwMH0seyJlZmZlY3QiOiJOb0V4ZWN1dGUiLCJrZXkiOiJub2RlLmt1YmVybmV0ZXMuaW8vdW5yZWFjaGFibGUiLCJvcGVyYXRvciI6IkV4aXN0cyIsInRvbGVyYXRpb25TZWNvbmRzIjozMDB9XSwidm9sdW1lcyI6W3siY29uZmlnTWFwIjp7ImRlZmF1bHRNb2RlIjo0MjAsIm5hbWUiOiJrdWJlc2hhcmstbmdpbngtY29uZmlnLW1hcCJ9LCJuYW1lIjoibmdpbngtY29uZmlnIn0seyJuYW1lIjoia3ViZS1hcGktYWNjZXNzLXpmaDZ0IiwicHJvamVjdGVkIjp7ImRlZmF1bHRNb2RlIjo0MjAsInNvdXJjZXMiOlt7InNlcnZpY2VBY2NvdW50VG9rZW4iOnsiZXhwaXJhdGlvblNlY29uZHMiOjM2MDcsInBhdGgiOiJ0b2tlbiJ9fSx7ImNvbmZpZ01hcCI6eyJpdGVtcyI6W3sia2V5IjoiY2EuY3J0IiwicGF0aCI6ImNhLmNydCJ9XSwibmFtZSI6Imt1YmUtcm9vdC1jYS5jcnQifX0seyJkb3dud2FyZEFQSSI6eyJpdGVtcyI6W3siZmllbGRSZWYiOnsiYXBpVmVyc2lvbiI6InYxIiwiZmllbGRQYXRoIjoibWV0YWRhdGEubmFtZXNwYWNlIn0sInBhdGgiOiJuYW1lc3BhY2UifV19fV19fV19LCJzdGF0dXMiOnsiY29uZGl0aW9ucyI6W3sibGFzdFRyYW5zaXRpb25UaW1lIjoiMjAyNC0wMy0xNlQwOTo1NzozOS4wMDAwMDBaIiwic3RhdHVzIjoiVHJ1ZSIsInR5cGUiOiJJbml0aWFsaXplZCJ9LHsibGFzdFRyYW5zaXRpb25UaW1lIjoiMjAyNC0wMy0yMlQwNTo0NjowNi4wMDAwMDBaIiwic3RhdHVzIjoiVHJ1ZSIsInR5cGUiOiJSZWFkeSJ9LHsibGFzdFRyYW5zaXRpb25UaW1lIjoiMjAyNC0wMy0yMlQwNTo0NjowNi4wMDAwMDBaIiwic3RhdHVzIjoiVHJ1ZSIsInR5cGUiOiJDb250YWluZXJzUmVhZHkifSx7Imxhc3RUcmFuc2l0aW9uVGltZSI6IjIwMjQtMDMtMTZUMDk6NTc6MzkuMDAwMDAwWiIsInN0YXR1cyI6IlRydWUiLCJ0eXBlIjoiUG9kU2NoZWR1bGVkIn1dLCJjb250YWluZXJTdGF0dXNlcyI6W3siYWxsb2NhdGVkUmVzb3VyY2VzIjp7fSwiY29udGFpbmVySUQiOiJkb2NrZXI6Ly8zNjdmMWRhNmU1ZmQzMWFjZGFlZmI5ZmY5NTU4NzBkZWJkMzdiNjBiNzMzNWM5NjAzOTM4ZWU1NTkxNGU0N2RkIiwiaW1hZ2UiOiJrdWJlc2hhcmsvZnJvbnQ6djUyLjEuNzUiLCJpbWFnZUlEIjoiZG9ja2VyLXB1bGxhYmxlOi8va3ViZXNoYXJrL2Zyb250QHNoYTI1Njo3ODE5YWMxZDI1ODM5OWQ3ZmJmNzVmNTFmODc3YzI4ZTJiZjVhZDVkYjc5ZDdiYTA5Y2EyYjU3NjA3ZDEzYjBhIiwibGFzdFN0YXRlIjp7InRlcm1pbmF0ZWQiOnsiY29udGFpbmVySUQiOiJkb2NrZXI6Ly8wNzQ0YmU3YWJkZWNjOTdhMjRiODE5YzU3MWFiNWNkNGZjNWI1MDBkOGQ3ZDk5ZDJmMzU0ZmFjMjBiNzk3NmQyIiwiZXhpdENvZGUiOjEsImZpbmlzaGVkQXQiOiIyMDI0LTAzLTIyVDA1OjQ1OjU5LjAwMDAwMFoiLCJyZWFzb24iOiJFcnJvciIsInN0YXJ0ZWRBdCI6IjIwMjQtMDMtMjJUMDU6NDU6NTMuMDAwMDAwWiJ9fSwibmFtZSI6Imt1YmVzaGFyay1mcm9udCIsInJlYWR5Ijp0cnVlLCJyZXN0YXJ0Q291bnQiOjQsInN0YXJ0ZWQiOnRydWUsInN0YXRlIjp7InJ1bm5pbmciOnsic3RhcnRlZEF0IjoiMjAyNC0wMy0yMlQwNTo0NjowMy4wMDAwMDBaIn19fV0sImhvc3RJUCI6IjE5Mi4xNjguMTE3LjUxIiwicGhhc2UiOiJSdW5uaW5nIiwicG9kSVAiOiIxMC4yNDQuMS41OCIsInBvZElQcyI6W3siaXAiOiIxMC4yNDQuMS41OCJ9XSwicW9zQ2xhc3MiOiJCdXJzdGFibGUiLCJzdGFydFRpbWUiOiIyMDI0LTAzLTE2VDA5OjU3OjM5LjAwMDAwMFoifX0seyJtZXRhZGF0YSI6eyJhbm5vdGF0aW9ucyI6e30sImNyZWF0aW9uVGltZXN0YW1wIjoiMjAyNC0wMy0xNlQwOTo1NzozOS4wMDAwMDBaIiwiZ2VuZXJhdGVOYW1lIjoia3ViZXNoYXJrLWh1Yi01Y2ZiY2ZkNDc4LSIsImxhYmVscyI6eyJhcHAua3ViZXJuZXRlcy5pby9pbnN0YW5jZSI6Imt1YmVzaGFyayIsImFwcC5rdWJlcm5ldGVzLmlvL21hbmFnZWQtYnkiOiJIZWxtIiwiYXBwLmt1YmVybmV0ZXMuaW8vbmFtZSI6Imt1YmVzaGFyayIsImFwcC5rdWJlcm5ldGVzLmlvL3ZlcnNpb24iOiI1Mi4xLjc1IiwiYXBwLmt1YmVzaGFyay5jby9hcHAiOiJodWIiLCJoZWxtLnNoL2NoYXJ0Ijoia3ViZXNoYXJrLTUyLjEuNzUiLCJwb2QtdGVtcGxhdGUtaGFzaCI6IjVjZmJjZmQ0NzgifSwibWFuYWdlZEZpZWxkcyI6W3siYXBpVmVyc2lvbiI6InYxIiwiZmllbGRzVHlwZSI6IkZpZWxkc1YxIiwiZmllbGRzVjEiOnsiZjptZXRhZGF0YSI6eyJmOmdlbmVyYXRlTmFtZSI6e30sImY6bGFiZWxzIjp7Ii4iOnt9LCJmOmFwcC5rdWJlcm5ldGVzLmlvL2luc3RhbmNlIjp7fSwiZjphcHAua3ViZXJuZXRlcy5pby9tYW5hZ2VkLWJ5Ijp7fSwiZjphcHAua3ViZXJuZXRlcy5pby9uYW1lIjp7fSwiZjphcHAua3ViZXJuZXRlcy5pby92ZXJzaW9uIjp7fSwiZjphcHAua3ViZXNoYXJrLmNvL2FwcCI6e30sImY6aGVsbS5zaC9jaGFydCI6e30sImY6cG9kLXRlbXBsYXRlLWhhc2giOnt9fSwiZjpvd25lclJlZmVyZW5jZXMiOnsiLiI6e30sIms6e1widWlkXCI6XCIyNzAyOGM2Ny1jYjRhLTQ0ZDUtOThlMi0zOTQxMWEzYjRiOGRcIn0iOnt9fX0sImY6c3BlYyI6eyJmOmNvbnRhaW5lcnMiOnsiazp7XCJuYW1lXCI6XCJrdWJlc2hhcmstaHViXCJ9Ijp7Ii4iOnt9LCJmOmNvbW1hbmQiOnt9LCJmOmVudiI6eyIuIjp7fSwiazp7XCJuYW1lXCI6XCJLVUJFU0hBUktfQ0xPVURfQVBJX1VSTFwifSI6eyIuIjp7fSwiZjpuYW1lIjp7fSwiZjp2YWx1ZSI6e319LCJrOntcIm5hbWVcIjpcIlBPRF9OQU1FXCJ9Ijp7Ii4iOnt9LCJmOm5hbWUiOnt9LCJmOnZhbHVlRnJvbSI6eyIuIjp7fSwiZjpmaWVsZFJlZiI6e319fSwiazp7XCJuYW1lXCI6XCJQT0RfTkFNRVNQQUNFXCJ9Ijp7Ii4iOnt9LCJmOm5hbWUiOnt9LCJmOnZhbHVlRnJvbSI6eyIuIjp7fSwiZjpmaWVsZFJlZiI6e319fX0sImY6aW1hZ2UiOnt9LCJmOmltYWdlUHVsbFBvbGljeSI6e30sImY6bGl2ZW5lc3NQcm9iZSI6eyIuIjp7fSwiZjpmYWlsdXJlVGhyZXNob2xkIjp7fSwiZjppbml0aWFsRGVsYXlTZWNvbmRzIjp7fSwiZjpwZXJpb2RTZWNvbmRzIjp7fSwiZjpzdWNjZXNzVGhyZXNob2xkIjp7fSwiZjp0Y3BTb2NrZXQiOnsiLiI6e30sImY6cG9ydCI6e319LCJmOnRpbWVvdXRTZWNvbmRzIjp7fX0sImY6bmFtZSI6e30sImY6cmVhZGluZXNzUHJvYmUiOnsiLiI6e30sImY6ZmFpbHVyZVRocmVzaG9sZCI6e30sImY6aW5pdGlhbERlbGF5U2Vjb25kcyI6e30sImY6cGVyaW9kU2Vjb25kcyI6e30sImY6c3VjY2Vzc1RocmVzaG9sZCI6e30sImY6dGNwU29ja2V0Ijp7Ii4iOnt9LCJmOnBvcnQiOnt9fSwiZjp0aW1lb3V0U2Vjb25kcyI6e319LCJmOnJlc291cmNlcyI6eyIuIjp7fSwiZjpsaW1pdHMiOnsiLiI6e30sImY6Y3B1Ijp7fSwiZjptZW1vcnkiOnt9fSwiZjpyZXF1ZXN0cyI6eyIuIjp7fSwiZjpjcHUiOnt9LCJmOm1lbW9yeSI6e319fSwiZjp0ZXJtaW5hdGlvbk1lc3NhZ2VQYXRoIjp7fSwiZjp0ZXJtaW5hdGlvbk1lc3NhZ2VQb2xpY3kiOnt9LCJmOnZvbHVtZU1vdW50cyI6eyIuIjp7fSwiazp7XCJtb3VudFBhdGhcIjpcIi9ldGMvc2FtbC94NTA5XCJ9Ijp7Ii4iOnt9LCJmOm1vdW50UGF0aCI6e30sImY6bmFtZSI6e30sImY6cmVhZE9ubHkiOnt9fX19fSwiZjpkbnNQb2xpY3kiOnt9LCJmOmVuYWJsZVNlcnZpY2VMaW5rcyI6e30sImY6cmVzdGFydFBvbGljeSI6e30sImY6c2NoZWR1bGVyTmFtZSI6e30sImY6c2VjdXJpdHlDb250ZXh0Ijp7fSwiZjpzZXJ2aWNlQWNjb3VudCI6e30sImY6c2VydmljZUFjY291bnROYW1lIjp7fSwiZjp0ZXJtaW5hdGlvbkdyYWNlUGVyaW9kU2Vjb25kcyI6e30sImY6dm9sdW1lcyI6eyIuIjp7fSwiazp7XCJuYW1lXCI6XCJzYW1sLXg1MDktdm9sdW1lXCJ9Ijp7Ii4iOnt9LCJmOm5hbWUiOnt9LCJmOnByb2plY3RlZCI6eyIuIjp7fSwiZjpkZWZhdWx0TW9kZSI6e30sImY6c291cmNlcyI6e319fX19fSwibWFuYWdlciI6Imt1YmUtY29udHJvbGxlci1tYW5hZ2VyIiwib3BlcmF0aW9uIjoiVXBkYXRlIiwidGltZSI6IjIwMjQtMDMtMTZUMDk6NTc6MzkuMDAwMDAwWiJ9LHsiYXBpVmVyc2lvbiI6InYxIiwiZmllbGRzVHlwZSI6IkZpZWxkc1YxIiwiZmllbGRzVjEiOnsiZjpzdGF0dXMiOnsiZjpjb25kaXRpb25zIjp7Ims6e1widHlwZVwiOlwiQ29udGFpbmVyc1JlYWR5XCJ9Ijp7Ii4iOnt9LCJmOmxhc3RQcm9iZVRpbWUiOnt9LCJmOmxhc3RUcmFuc2l0aW9uVGltZSI6e30sImY6c3RhdHVzIjp7fSwiZjp0eXBlIjp7fX0sIms6e1widHlwZVwiOlwiSW5pdGlhbGl6ZWRcIn0iOnsiLiI6e30sImY6bGFzdFByb2JlVGltZSI6e30sImY6bGFzdFRyYW5zaXRpb25UaW1lIjp7fSwiZjpzdGF0dXMiOnt9LCJmOnR5cGUiOnt9fSwiazp7XCJ0eXBlXCI6XCJSZWFkeVwifSI6eyIuIjp7fSwiZjpsYXN0UHJvYmVUaW1lIjp7fSwiZjpsYXN0VHJhbnNpdGlvblRpbWUiOnt9LCJmOnN0YXR1cyI6e30sImY6dHlwZSI6e319fSwiZjpjb250YWluZXJTdGF0dXNlcyI6e30sImY6aG9zdElQIjp7fSwiZjpwaGFzZSI6e30sImY6cG9kSVAiOnt9LCJmOnBvZElQcyI6eyIuIjp7fSwiazp7XCJpcFwiOlwiMTAuMjQ0LjEuNTVcIn0iOnsiLiI6e30sImY6aXAiOnt9fX0sImY6c3RhcnRUaW1lIjp7fX19LCJtYW5hZ2VyIjoia3ViZWxldCIsIm9wZXJhdGlvbiI6IlVwZGF0ZSIsInN1YnJlc291cmNlIjoic3RhdHVzIiwidGltZSI6IjIwMjQtMDMtMjJUMDU6NDU6NTAuMDAwMDAwWiJ9XSwibmFtZSI6Imt1YmVzaGFyay1odWItNWNmYmNmZDQ3OC0yajh4NiIsIm5hbWVzcGFjZSI6ImRlZmF1bHQiLCJvd25lclJlZmVyZW5jZXMiOlt7ImFwaVZlcnNpb24iOiJhcHBzL3YxIiwiYmxvY2tPd25lckRlbGV0aW9uIjp0cnVlLCJjb250cm9sbGVyIjp0cnVlLCJraW5kIjoiUmVwbGljYVNldCIsIm5hbWUiOiJrdWJlc2hhcmstaHViLTVjZmJjZmQ0NzgiLCJ1aWQiOiIyNzAyOGM2Ny1jYjRhLTQ0ZDUtOThlMi0zOTQxMWEzYjRiOGQifV0sInJlc291cmNlVmVyc2lvbiI6IjE4MDg1MjEiLCJ1aWQiOiI1NDcwY2U1Zi04NTc5LTRlMDYtYjY1Mi1lOGZlNDZlNDFmMmEifSwic3BlYyI6eyJjb250YWluZXJzIjpbeyJjb21tYW5kIjpbIi4vaHViIiwiLXBvcnQiLCI4MDgwIl0sImVudiI6W3sibmFtZSI6IlBPRF9OQU1FIiwidmFsdWVGcm9tIjp7ImZpZWxkUmVmIjp7ImFwaVZlcnNpb24iOiJ2MSIsImZpZWxkUGF0aCI6Im1ldGFkYXRhLm5hbWUifX19LHsibmFtZSI6IlBPRF9OQU1FU1BBQ0UiLCJ2YWx1ZUZyb20iOnsiZmllbGRSZWYiOnsiYXBpVmVyc2lvbiI6InYxIiwiZmllbGRQYXRoIjoibWV0YWRhdGEubmFtZXNwYWNlIn19fSx7Im5hbWUiOiJLVUJFU0hBUktfQ0xPVURfQVBJX1VSTCIsInZhbHVlIjoiaHR0cHM6Ly9hcGkua3ViZXNoYXJrLmNvIn1dLCJpbWFnZSI6ImRvY2tlci5pby9rdWJlc2hhcmsvaHViOnY1Mi4xLjc1IiwiaW1hZ2VQdWxsUG9saWN5IjoiQWx3YXlzIiwibGl2ZW5lc3NQcm9iZSI6eyJmYWlsdXJlVGhyZXNob2xkIjozLCJpbml0aWFsRGVsYXlTZWNvbmRzIjozLCJwZXJpb2RTZWNvbmRzIjoxLCJzdWNjZXNzVGhyZXNob2xkIjoxLCJ0Y3BTb2NrZXQiOnsicG9ydCI6ODA4MH0sInRpbWVvdXRTZWNvbmRzIjoxfSwibmFtZSI6Imt1YmVzaGFyay1odWIiLCJyZWFkaW5lc3NQcm9iZSI6eyJmYWlsdXJlVGhyZXNob2xkIjozLCJpbml0aWFsRGVsYXlTZWNvbmRzIjozLCJwZXJpb2RTZWNvbmRzIjoxLCJzdWNjZXNzVGhyZXNob2xkIjoxLCJ0Y3BTb2NrZXQiOnsicG9ydCI6ODA4MH0sInRpbWVvdXRTZWNvbmRzIjoxfSwicmVzb3VyY2VzIjp7ImxpbWl0cyI6eyJjcHUiOiI3NTBtIiwibWVtb3J5IjoiMUdpIn0sInJlcXVlc3RzIjp7ImNwdSI6IjUwbSIsIm1lbW9yeSI6IjUwTWkifX0sInRlcm1pbmF0aW9uTWVzc2FnZVBhdGgiOiIvZGV2L3Rlcm1pbmF0aW9uLWxvZyIsInRlcm1pbmF0aW9uTWVzc2FnZVBvbGljeSI6IkZpbGUiLCJ2b2x1bWVNb3VudHMiOlt7Im1vdW50UGF0aCI6Ii9ldGMvc2FtbC94NTA5IiwibmFtZSI6InNhbWwteDUwOS12b2x1bWUiLCJyZWFkT25seSI6dHJ1ZX0seyJtb3VudFBhdGgiOiIvdmFyL3J1bi9zZWNyZXRzL2t1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQiLCJuYW1lIjoia3ViZS1hcGktYWNjZXNzLTQybmhtIiwicmVhZE9ubHkiOnRydWV9XX1dLCJkbnNQb2xpY3kiOiJDbHVzdGVyRmlyc3RXaXRoSG9zdE5ldCIsImVuYWJsZVNlcnZpY2VMaW5rcyI6dHJ1ZSwibm9kZU5hbWUiOiJub2RlLTEiLCJub2RlU2VsZWN0b3IiOnt9LCJvdmVyaGVhZCI6e30sInByZWVtcHRpb25Qb2xpY3kiOiJQcmVlbXB0TG93ZXJQcmlvcml0eSIsInByaW9yaXR5IjowLCJyZXN0YXJ0UG9saWN5IjoiQWx3YXlzIiwic2NoZWR1bGVyTmFtZSI6ImRlZmF1bHQtc2NoZWR1bGVyIiwic2VjdXJpdHlDb250ZXh0Ijp7fSwic2VydmljZUFjY291bnQiOiJrdWJlc2hhcmstc2VydmljZS1hY2NvdW50Iiwic2VydmljZUFjY291bnROYW1lIjoia3ViZXNoYXJrLXNlcnZpY2UtYWNjb3VudCIsInRlcm1pbmF0aW9uR3JhY2VQZXJpb2RTZWNvbmRzIjozMCwidG9sZXJhdGlvbnMiOlt7ImVmZmVjdCI6Ik5vRXhlY3V0ZSIsImtleSI6Im5vZGUua3ViZXJuZXRlcy5pby9ub3QtcmVhZHkiLCJvcGVyYXRvciI6IkV4aXN0cyIsInRvbGVyYXRpb25TZWNvbmRzIjozMDB9LHsiZWZmZWN0IjoiTm9FeGVjdXRlIiwia2V5Ijoibm9kZS5rdWJlcm5ldGVzLmlvL3VucmVhY2hhYmxlIiwib3BlcmF0b3IiOiJFeGlzdHMiLCJ0b2xlcmF0aW9uU2Vjb25kcyI6MzAwfV0sInZvbHVtZXMiOlt7Im5hbWUiOiJzYW1sLXg1MDktdm9sdW1lIiwicHJvamVjdGVkIjp7ImRlZmF1bHRNb2RlIjo0MjAsInNvdXJjZXMiOlt7InNlY3JldCI6eyJpdGVtcyI6W3sia2V5IjoiQVVUSF9TQU1MX1g1MDlfQ1JUIiwicGF0aCI6Imt1YmVzaGFyay5jcnQifV0sIm5hbWUiOiJrdWJlc2hhcmstc2FtbC14NTA5LWNydC1zZWNyZXQifX0seyJzZWNyZXQiOnsiaXRlbXMiOlt7ImtleSI6IkFVVEhfU0FNTF9YNTA5X0tFWSIsInBhdGgiOiJrdWJlc2hhcmsua2V5In1dLCJuYW1lIjoia3ViZXNoYXJrLXNhbWwteDUwOS1rZXktc2VjcmV0In19XX19LHsibmFtZSI6Imt1YmUtYXBpLWFjY2Vzcy00Mm5obSIsInByb2plY3RlZCI6eyJkZWZhdWx0TW9kZSI6NDIwLCJzb3VyY2VzIjpbeyJzZXJ2aWNlQWNjb3VudFRva2VuIjp7ImV4cGlyYXRpb25TZWNvbmRzIjozNjA3LCJwYXRoIjoidG9rZW4ifX0seyJjb25maWdNYXAiOnsiaXRlbXMiOlt7ImtleSI6ImNhLmNydCIsInBhdGgiOiJjYS5jcnQifV0sIm5hbWUiOiJrdWJlLXJvb3QtY2EuY3J0In19LHsiZG93bndhcmRBUEkiOnsiaXRlbXMiOlt7ImZpZWxkUmVmIjp7ImFwaVZlcnNpb24iOiJ2MSIsImZpZWxkUGF0aCI6Im1ldGFkYXRhLm5hbWVzcGFjZSJ9LCJwYXRoIjoibmFtZXNwYWNlIn1dfX1dfX1dfSwic3RhdHVzIjp7ImNvbmRpdGlvbnMiOlt7Imxhc3RUcmFuc2l0aW9uVGltZSI6IjIwMjQtMDMtMTZUMDk6NTc6MzkuMDAwMDAwWiIsInN0YXR1cyI6IlRydWUiLCJ0eXBlIjoiSW5pdGlhbGl6ZWQifSx7Imxhc3RUcmFuc2l0aW9uVGltZSI6IjIwMjQtMDMtMjJUMDU6NDU6NTAuMDAwMDAwWiIsInN0YXR1cyI6IlRydWUiLCJ0eXBlIjoiUmVhZHkifSx7Imxhc3RUcmFuc2l0aW9uVGltZSI6IjIwMjQtMDMtMjJUMDU6NDU6NTAuMDAwMDAwWiIsInN0YXR1cyI6IlRydWUiLCJ0eXBlIjoiQ29udGFpbmVyc1JlYWR5In0seyJsYXN0VHJhbnNpdGlvblRpbWUiOiIyMDI0LTAzLTE2VDA5OjU3OjM5LjAwMDAwMFoiLCJzdGF0dXMiOiJUcnVlIiwidHlwZSI6IlBvZFNjaGVkdWxlZCJ9XSwiY29udGFpbmVyU3RhdHVzZXMiOlt7ImFsbG9jYXRlZFJlc291cmNlcyI6e30sImNvbnRhaW5lcklEIjoiZG9ja2VyOi8vZTA5ZTZmYTE3MTEwZDQwMjAyNzE0YmNmNWI1MmQwZDA3MzhmZGZkODRjN2FhNGJhY2FkMDgxNzhlNzBiYjY2MiIsImltYWdlIjoia3ViZXNoYXJrL2h1Yjp2NTIuMS43NSIsImltYWdlSUQiOiJkb2NrZXItcHVsbGFibGU6Ly9rdWJlc2hhcmsvaHViQHNoYTI1Njo5ZTEwNWU1NjYzNjY3ZGJkMDE4ZTk0ZDkwMzI2OTkyMTdlNTliOWMwZGU1ZWVkNTYzOTYzYWI2MGE2NGEwNTY0IiwibGFzdFN0YXRlIjp7InRlcm1pbmF0ZWQiOnsiY29udGFpbmVySUQiOiJkb2NrZXI6Ly8wMzU5NTdjYzcwZDAxZTRlYjU2MDgwYTFmYTAxZDdiN2I0MjdkZGIxZjc0N2FjOTE2NDI0YmFlZmU0YTdiZTQ4IiwiZXhpdENvZGUiOjI1NSwiZmluaXNoZWRBdCI6IjIwMjQtMDMtMjJUMDU6NDU6MTUuMDAwMDAwWiIsInJlYXNvbiI6IkVycm9yIiwic3RhcnRlZEF0IjoiMjAyNC0wMy0yMVQwNjozMDoxNS4wMDAwMDBaIn19LCJuYW1lIjoia3ViZXNoYXJrLWh1YiIsInJlYWR5Ijp0cnVlLCJyZXN0YXJ0Q291bnQiOjIsInN0YXJ0ZWQiOnRydWUsInN0YXRlIjp7InJ1bm5pbmciOnsic3RhcnRlZEF0IjoiMjAyNC0wMy0yMlQwNTo0NTo0Ny4wMDAwMDBaIn19fV0sImhvc3RJUCI6IjE5Mi4xNjguMTE3LjUxIiwicGhhc2UiOiJSdW5uaW5nIiwicG9kSVAiOiIxMC4yNDQuMS41NSIsInBvZElQcyI6W3siaXAiOiIxMC4yNDQuMS41NSJ9XSwicW9zQ2xhc3MiOiJCdXJzdGFibGUiLCJzdGFydFRpbWUiOiIyMDI0LTAzLTE2VDA5OjU3OjM5LjAwMDAwMFoifX0seyJtZXRhZGF0YSI6eyJhbm5vdGF0aW9ucyI6e30sImNyZWF0aW9uVGltZXN0YW1wIjoiMjAyNC0wMy0yM1QwODoxNDo1My4wMDAwMDBaIiwiZ2VuZXJhdGVOYW1lIjoia3ViZXNoYXJrLXdvcmtlci1kYWVtb24tc2V0LSIsImxhYmVscyI6eyJhcHAua3ViZXJuZXRlcy5pby9pbnN0YW5jZSI6Imt1YmVzaGFyayIsImFwcC5rdWJlcm5ldGVzLmlvL21hbmFnZWQtYnkiOiJIZWxtIiwiYXBwLmt1YmVybmV0ZXMuaW8vbmFtZSI6Imt1YmVzaGFyayIsImFwcC5rdWJlcm5ldGVzLmlvL3ZlcnNpb24iOiI1Mi4xLjc1IiwiYXBwLmt1YmVzaGFyay5jby9hcHAiOiJ3b3JrZXIiLCJjb250cm9sbGVyLXJldmlzaW9uLWhhc2giOiI5ZmQ4ZjdjNTQiLCJoZWxtLnNoL2NoYXJ0Ijoia3ViZXNoYXJrLTUyLjEuNzUiLCJwb2QtdGVtcGxhdGUtZ2VuZXJhdGlvbiI6IjEifSwibWFuYWdlZEZpZWxkcyI6W3siYXBpVmVyc2lvbiI6InYxIiwiZmllbGRzVHlwZSI6IkZpZWxkc1YxIiwiZmllbGRzVjEiOnsiZjptZXRhZGF0YSI6eyJmOmdlbmVyYXRlTmFtZSI6e30sImY6bGFiZWxzIjp7Ii4iOnt9LCJmOmFwcC5rdWJlcm5ldGVzLmlvL2luc3RhbmNlIjp7fSwiZjphcHAua3ViZXJuZXRlcy5pby9tYW5hZ2VkLWJ5Ijp7fSwiZjphcHAua3ViZXJuZXRlcy5pby9uYW1lIjp7fSwiZjphcHAua3ViZXJuZXRlcy5pby92ZXJzaW9uIjp7fSwiZjphcHAua3ViZXNoYXJrLmNvL2FwcCI6e30sImY6Y29udHJvbGxlci1yZXZpc2lvbi1oYXNoIjp7fSwiZjpoZWxtLnNoL2NoYXJ0Ijp7fSwiZjpwb2QtdGVtcGxhdGUtZ2VuZXJhdGlvbiI6e319LCJmOm93bmVyUmVmZXJlbmNlcyI6eyIuIjp7fSwiazp7XCJ1aWRcIjpcIjA1YWUzMWVhLWVkZjgtNDdjNi05OWFmLTBhMmM4MWIyY2VhZVwifSI6e319fSwiZjpzcGVjIjp7ImY6YWZmaW5pdHkiOnsiLiI6e30sImY6bm9kZUFmZmluaXR5Ijp7Ii4iOnt9LCJmOnJlcXVpcmVkRHVyaW5nU2NoZWR1bGluZ0lnbm9yZWREdXJpbmdFeGVjdXRpb24iOnt9fX0sImY6Y29udGFpbmVycyI6eyJrOntcIm5hbWVcIjpcInNuaWZmZXJcIn0iOnsiLiI6e30sImY6Y29tbWFuZCI6e30sImY6ZW52Ijp7Ii4iOnt9LCJrOntcIm5hbWVcIjpcIktVQkVTSEFSS19DTE9VRF9BUElfVVJMXCJ9Ijp7Ii4iOnt9LCJmOm5hbWUiOnt9LCJmOnZhbHVlIjp7fX0sIms6e1wibmFtZVwiOlwiUE9EX05BTUVcIn0iOnsiLiI6e30sImY6bmFtZSI6e30sImY6dmFsdWVGcm9tIjp7Ii4iOnt9LCJmOmZpZWxkUmVmIjp7fX19LCJrOntcIm5hbWVcIjpcIlBPRF9OQU1FU1BBQ0VcIn0iOnsiLiI6e30sImY6bmFtZSI6e30sImY6dmFsdWVGcm9tIjp7Ii4iOnt9LCJmOmZpZWxkUmVmIjp7fX19LCJrOntcIm5hbWVcIjpcIlRDUF9TVFJFQU1fQ0hBTk5FTF9USU1FT1VUX01TXCJ9Ijp7Ii4iOnt9LCJmOm5hbWUiOnt9LCJmOnZhbHVlIjp7fX19LCJmOmltYWdlIjp7fSwiZjppbWFnZVB1bGxQb2xpY3kiOnt9LCJmOmxpdmVuZXNzUHJvYmUiOnsiLiI6e30sImY6ZmFpbHVyZVRocmVzaG9sZCI6e30sImY6aW5pdGlhbERlbGF5U2Vjb25kcyI6e30sImY6cGVyaW9kU2Vjb25kcyI6e30sImY6c3VjY2Vzc1RocmVzaG9sZCI6e30sImY6dGNwU29ja2V0Ijp7Ii4iOnt9LCJmOnBvcnQiOnt9fSwiZjp0aW1lb3V0U2Vjb25kcyI6e319LCJmOm5hbWUiOnt9LCJmOnBvcnRzIjp7Ii4iOnt9LCJrOntcImNvbnRhaW5lclBvcnRcIjo0OTEwMCxcInByb3RvY29sXCI6XCJUQ1BcIn0iOnsiLiI6e30sImY6Y29udGFpbmVyUG9ydCI6e30sImY6aG9zdFBvcnQiOnt9LCJmOm5hbWUiOnt9LCJmOnByb3RvY29sIjp7fX19LCJmOnJlYWRpbmVzc1Byb2JlIjp7Ii4iOnt9LCJmOmZhaWx1cmVUaHJlc2hvbGQiOnt9LCJmOmluaXRpYWxEZWxheVNlY29uZHMiOnt9LCJmOnBlcmlvZFNlY29uZHMiOnt9LCJmOnN1Y2Nlc3NUaHJlc2hvbGQiOnt9LCJmOnRjcFNvY2tldCI6eyIuIjp7fSwiZjpwb3J0Ijp7fX0sImY6dGltZW91dFNlY29uZHMiOnt9fSwiZjpyZXNvdXJjZXMiOnsiLiI6e30sImY6bGltaXRzIjp7Ii4iOnt9LCJmOmNwdSI6e30sImY6bWVtb3J5Ijp7fX0sImY6cmVxdWVzdHMiOnsiLiI6e30sImY6Y3B1Ijp7fSwiZjptZW1vcnkiOnt9fX0sImY6c2VjdXJpdHlDb250ZXh0Ijp7Ii4iOnt9LCJmOmNhcGFiaWxpdGllcyI6eyIuIjp7fSwiZjphZGQiOnt9LCJmOmRyb3AiOnt9fX0sImY6dGVybWluYXRpb25NZXNzYWdlUGF0aCI6e30sImY6dGVybWluYXRpb25NZXNzYWdlUG9saWN5Ijp7fSwiZjp2b2x1bWVNb3VudHMiOnsiLiI6e30sIms6e1wibW91bnRQYXRoXCI6XCIvYXBwL2RhdGFcIn0iOnsiLiI6e30sImY6bW91bnRQYXRoIjp7fSwiZjpuYW1lIjp7fX0sIms6e1wibW91bnRQYXRoXCI6XCIvaG9zdHByb2NcIn0iOnsiLiI6e30sImY6bW91bnRQYXRoIjp7fSwiZjpuYW1lIjp7fSwiZjpyZWFkT25seSI6e319LCJrOntcIm1vdW50UGF0aFwiOlwiL3N5c1wifSI6eyIuIjp7fSwiZjptb3VudFBhdGgiOnt9LCJmOm5hbWUiOnt9LCJmOnJlYWRPbmx5Ijp7fX19fSwiazp7XCJuYW1lXCI6XCJ0cmFjZXJcIn0iOnsiLiI6e30sImY6Y29tbWFuZCI6e30sImY6ZW52Ijp7Ii4iOnt9LCJrOntcIm5hbWVcIjpcIlBPRF9OQU1FXCJ9Ijp7Ii4iOnt9LCJmOm5hbWUiOnt9LCJmOnZhbHVlRnJvbSI6eyIuIjp7fSwiZjpmaWVsZFJlZiI6e319fSwiazp7XCJuYW1lXCI6XCJQT0RfTkFNRVNQQUNFXCJ9Ijp7Ii4iOnt9LCJmOm5hbWUiOnt9LCJmOnZhbHVlRnJvbSI6eyIuIjp7fSwiZjpmaWVsZFJlZiI6e319fX0sImY6aW1hZ2UiOnt9LCJmOmltYWdlUHVsbFBvbGljeSI6e30sImY6bmFtZSI6e30sImY6cmVzb3VyY2VzIjp7Ii4iOnt9LCJmOmxpbWl0cyI6eyIuIjp7fSwiZjpjcHUiOnt9LCJmOm1lbW9yeSI6e319LCJmOnJlcXVlc3RzIjp7Ii4iOnt9LCJmOmNwdSI6e30sImY6bWVtb3J5Ijp7fX19LCJmOnNlY3VyaXR5Q29udGV4dCI6eyIuIjp7fSwiZjpjYXBhYmlsaXRpZXMiOnsiLiI6e30sImY6YWRkIjp7fSwiZjpkcm9wIjp7fX19LCJmOnRlcm1pbmF0aW9uTWVzc2FnZVBhdGgiOnt9LCJmOnRlcm1pbmF0aW9uTWVzc2FnZVBvbGljeSI6e30sImY6dm9sdW1lTW91bnRzIjp7Ii4iOnt9LCJrOntcIm1vdW50UGF0aFwiOlwiL2FwcC9kYXRhXCJ9Ijp7Ii4iOnt9LCJmOm1vdW50UGF0aCI6e30sImY6bmFtZSI6e319LCJrOntcIm1vdW50UGF0aFwiOlwiL2hvc3Rwcm9jXCJ9Ijp7Ii4iOnt9LCJmOm1vdW50UGF0aCI6e30sImY6bmFtZSI6e30sImY6cmVhZE9ubHkiOnt9fSwiazp7XCJtb3VudFBhdGhcIjpcIi9zeXNcIn0iOnsiLiI6e30sImY6bW91bnRQYXRoIjp7fSwiZjpuYW1lIjp7fSwiZjpyZWFkT25seSI6e319fX19LCJmOmRuc1BvbGljeSI6e30sImY6ZW5hYmxlU2VydmljZUxpbmtzIjp7fSwiZjpob3N0TmV0d29yayI6e30sImY6aW5pdENvbnRhaW5lcnMiOnsiLiI6e30sIms6e1wibmFtZVwiOlwibG9hZC1wZi1yaW5nXCJ9Ijp7Ii4iOnt9LCJmOmltYWdlIjp7fSwiZjppbWFnZVB1bGxQb2xpY3kiOnt9LCJmOm5hbWUiOnt9LCJmOnJlc291cmNlcyI6e30sImY6c2VjdXJpdHlDb250ZXh0Ijp7Ii4iOnt9LCJmOmNhcGFiaWxpdGllcyI6eyIuIjp7fSwiZjphZGQiOnt9LCJmOmRyb3AiOnt9fX0sImY6dGVybWluYXRpb25NZXNzYWdlUGF0aCI6e30sImY6dGVybWluYXRpb25NZXNzYWdlUG9saWN5Ijp7fSwiZjp2b2x1bWVNb3VudHMiOnsiLiI6e30sIms6e1wibW91bnRQYXRoXCI6XCIvbGliL21vZHVsZXNcIn0iOnsiLiI6e30sImY6bW91bnRQYXRoIjp7fSwiZjpuYW1lIjp7fX19fX0sImY6cmVzdGFydFBvbGljeSI6e30sImY6c2NoZWR1bGVyTmFtZSI6e30sImY6c2VjdXJpdHlDb250ZXh0Ijp7fSwiZjpzZXJ2aWNlQWNjb3VudCI6e30sImY6c2VydmljZUFjY291bnROYW1lIjp7fSwiZjp0ZXJtaW5hdGlvbkdyYWNlUGVyaW9kU2Vjb25kcyI6e30sImY6dG9sZXJhdGlvbnMiOnt9LCJmOnZvbHVtZXMiOnsiLiI6e30sIms6e1wibmFtZVwiOlwiZGF0YVwifSI6eyIuIjp7fSwiZjplbXB0eURpciI6eyIuIjp7fSwiZjpzaXplTGltaXQiOnt9fSwiZjpuYW1lIjp7fX0sIms6e1wibmFtZVwiOlwibGliLW1vZHVsZXNcIn0iOnsiLiI6e30sImY6aG9zdFBhdGgiOnsiLiI6e30sImY6cGF0aCI6e30sImY6dHlwZSI6e319LCJmOm5hbWUiOnt9fSwiazp7XCJuYW1lXCI6XCJwcm9jXCJ9Ijp7Ii4iOnt9LCJmOmhvc3RQYXRoIjp7Ii4iOnt9LCJmOnBhdGgiOnt9LCJmOnR5cGUiOnt9fSwiZjpuYW1lIjp7fX0sIms6e1wibmFtZVwiOlwic3lzXCJ9Ijp7Ii4iOnt9LCJmOmhvc3RQYXRoIjp7Ii4iOnt9LCJmOnBhdGgiOnt9LCJmOnR5cGUiOnt9fSwiZjpuYW1lIjp7fX19fX0sIm1hbmFnZXIiOiJrdWJlLWNvbnRyb2xsZXItbWFuYWdlciIsIm9wZXJhdGlvbiI6IlVwZGF0ZSIsInRpbWUiOiIyMDI0LTAzLTIzVDA4OjE0OjUzLjAwMDAwMFoifSx7ImFwaVZlcnNpb24iOiJ2MSIsImZpZWxkc1R5cGUiOiJGaWVsZHNWMSIsImZpZWxkc1YxIjp7ImY6c3RhdHVzIjp7ImY6Y29uZGl0aW9ucyI6eyJrOntcInR5cGVcIjpcIkNvbnRhaW5lcnNSZWFkeVwifSI6eyIuIjp7fSwiZjpsYXN0UHJvYmVUaW1lIjp7fSwiZjpsYXN0VHJhbnNpdGlvblRpbWUiOnt9LCJmOnN0YXR1cyI6e30sImY6dHlwZSI6e319LCJrOntcInR5cGVcIjpcIkluaXRpYWxpemVkXCJ9Ijp7Ii4iOnt9LCJmOmxhc3RQcm9iZVRpbWUiOnt9LCJmOmxhc3RUcmFuc2l0aW9uVGltZSI6e30sImY6c3RhdHVzIjp7fSwiZjp0eXBlIjp7fX0sIms6e1widHlwZVwiOlwiUmVhZHlcIn0iOnsiLiI6e30sImY6bGFzdFByb2JlVGltZSI6e30sImY6bGFzdFRyYW5zaXRpb25UaW1lIjp7fSwiZjpzdGF0dXMiOnt9LCJmOnR5cGUiOnt9fX0sImY6Y29udGFpbmVyU3RhdHVzZXMiOnt9LCJmOmhvc3RJUCI6e30sImY6aW5pdENvbnRhaW5lclN0YXR1c2VzIjp7fSwiZjpwaGFzZSI6e30sImY6cG9kSVAiOnt9LCJmOnBvZElQcyI6eyIuIjp7fSwiazp7XCJpcFwiOlwiMTkyLjE2OC4xMTcuNTFcIn0iOnsiLiI6e30sImY6aXAiOnt9fX0sImY6c3RhcnRUaW1lIjp7fX19LCJtYW5hZ2VyIjoia3ViZWxldCIsIm9wZXJhdGlvbiI6IlVwZGF0ZSIsInN1YnJlc291cmNlIjoic3RhdHVzIiwidGltZSI6IjIwMjQtMDMtMjNUMDg6MTU6MDkuMDAwMDAwWiJ9XSwibmFtZSI6Imt1YmVzaGFyay13b3JrZXItZGFlbW9uLXNldC01c3Z3biIsIm5hbWVzcGFjZSI6ImRlZmF1bHQiLCJvd25lclJlZmVyZW5jZXMiOlt7ImFwaVZlcnNpb24iOiJhcHBzL3YxIiwiYmxvY2tPd25lckRlbGV0aW9uIjp0cnVlLCJjb250cm9sbGVyIjp0cnVlLCJraW5kIjoiRGFlbW9uU2V0IiwibmFtZSI6Imt1YmVzaGFyay13b3JrZXItZGFlbW9uLXNldCIsInVpZCI6IjA1YWUzMWVhLWVkZjgtNDdjNi05OWFmLTBhMmM4MWIyY2VhZSJ9XSwicmVzb3VyY2VWZXJzaW9uIjoiMTk0Mzk4NiIsInVpZCI6IjQ4NzQyYzM4LTAwNDAtNGM4Zi1hZTNiLTkyOTlkMzU5OTY3NCJ9LCJzcGVjIjp7ImFmZmluaXR5Ijp7Im5vZGVBZmZpbml0eSI6eyJyZXF1aXJlZER1cmluZ1NjaGVkdWxpbmdJZ25vcmVkRHVyaW5nRXhlY3V0aW9uIjp7Im5vZGVTZWxlY3RvclRlcm1zIjpbeyJtYXRjaEZpZWxkcyI6W3sia2V5IjoibWV0YWRhdGEubmFtZSIsIm9wZXJhdG9yIjoiSW4iLCJ2YWx1ZXMiOlsibm9kZS0xIl19XX1dfX19LCJjb250YWluZXJzIjpbeyJjb21tYW5kIjpbIi4vd29ya2VyIiwiLWkiLCJhbnkiLCItcG9ydCIsIjMwMDAxIiwiLW1ldHJpY3MtcG9ydCIsIjQ5MTAwIiwiLXVuaXhzb2NrZXQiLCItc2VydmljZW1lc2giLCItcHJvY2ZzIiwiL2hvc3Rwcm9jIiwiLWtlcm5lbC1tb2R1bGUiXSwiZW52IjpbeyJuYW1lIjoiUE9EX05BTUUiLCJ2YWx1ZUZyb20iOnsiZmllbGRSZWYiOnsiYXBpVmVyc2lvbiI6InYxIiwiZmllbGRQYXRoIjoibWV0YWRhdGEubmFtZSJ9fX0seyJuYW1lIjoiUE9EX05BTUVTUEFDRSIsInZhbHVlRnJvbSI6eyJmaWVsZFJlZiI6eyJhcGlWZXJzaW9uIjoidjEiLCJmaWVsZFBhdGgiOiJtZXRhZGF0YS5uYW1lc3BhY2UifX19LHsibmFtZSI6IlRDUF9TVFJFQU1fQ0hBTk5FTF9USU1FT1VUX01TIiwidmFsdWUiOiIxMDAwMCJ9LHsibmFtZSI6IktVQkVTSEFSS19DTE9VRF9BUElfVVJMIiwidmFsdWUiOiJodHRwczovL2FwaS5rdWJlc2hhcmsuY28ifV0sImltYWdlIjoiZG9ja2VyLmlvL2t1YmVzaGFyay93b3JrZXI6djUyLjEuNzUiLCJpbWFnZVB1bGxQb2xpY3kiOiJBbHdheXMiLCJsaXZlbmVzc1Byb2JlIjp7ImZhaWx1cmVUaHJlc2hvbGQiOjMsImluaXRpYWxEZWxheVNlY29uZHMiOjUsInBlcmlvZFNlY29uZHMiOjEsInN1Y2Nlc3NUaHJlc2hvbGQiOjEsInRjcFNvY2tldCI6eyJwb3J0IjozMDAwMX0sInRpbWVvdXRTZWNvbmRzIjoxfSwibmFtZSI6InNuaWZmZXIiLCJwb3J0cyI6W3siY29udGFpbmVyUG9ydCI6NDkxMDAsImhvc3RQb3J0Ijo0OTEwMCwibmFtZSI6Im1ldHJpY3MiLCJwcm90b2NvbCI6IlRDUCJ9XSwicmVhZGluZXNzUHJvYmUiOnsiZmFpbHVyZVRocmVzaG9sZCI6MywiaW5pdGlhbERlbGF5U2Vjb25kcyI6NSwicGVyaW9kU2Vjb25kcyI6MSwic3VjY2Vzc1RocmVzaG9sZCI6MSwidGNwU29ja2V0Ijp7InBvcnQiOjMwMDAxfSwidGltZW91dFNlY29uZHMiOjF9LCJyZXNvdXJjZXMiOnsibGltaXRzIjp7ImNwdSI6Ijc1MG0iLCJtZW1vcnkiOiIxR2kifSwicmVxdWVzdHMiOnsiY3B1IjoiNTBtIiwibWVtb3J5IjoiNTBNaSJ9fSwic2VjdXJpdHlDb250ZXh0Ijp7ImNhcGFiaWxpdGllcyI6eyJhZGQiOlsiTkVUX1JBVyIsIk5FVF9BRE1JTiIsIlNZU19BRE1JTiIsIlNZU19QVFJBQ0UiLCJEQUNfT1ZFUlJJREUiXSwiZHJvcCI6WyJBTEwiXX19LCJ0ZXJtaW5hdGlvbk1lc3NhZ2VQYXRoIjoiL2Rldi90ZXJtaW5hdGlvbi1sb2ciLCJ0ZXJtaW5hdGlvbk1lc3NhZ2VQb2xpY3kiOiJGaWxlIiwidm9sdW1lTW91bnRzIjpbeyJtb3VudFBhdGgiOiIvaG9zdHByb2MiLCJuYW1lIjoicHJvYyIsInJlYWRPbmx5Ijp0cnVlfSx7Im1vdW50UGF0aCI6Ii9zeXMiLCJuYW1lIjoic3lzIiwicmVhZE9ubHkiOnRydWV9LHsibW91bnRQYXRoIjoiL2FwcC9kYXRhIiwibmFtZSI6ImRhdGEifSx7Im1vdW50UGF0aCI6Ii92YXIvcnVuL3NlY3JldHMva3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudCIsIm5hbWUiOiJrdWJlLWFwaS1hY2Nlc3Mtc3pwc20iLCJyZWFkT25seSI6dHJ1ZX1dfSx7ImNvbW1hbmQiOlsiLi90cmFjZXIiLCItcHJvY2ZzIiwiL2hvc3Rwcm9jIl0sImVudiI6W3sibmFtZSI6IlBPRF9OQU1FIiwidmFsdWVGcm9tIjp7ImZpZWxkUmVmIjp7ImFwaVZlcnNpb24iOiJ2MSIsImZpZWxkUGF0aCI6Im1ldGFkYXRhLm5hbWUifX19LHsibmFtZSI6IlBPRF9OQU1FU1BBQ0UiLCJ2YWx1ZUZyb20iOnsiZmllbGRSZWYiOnsiYXBpVmVyc2lvbiI6InYxIiwiZmllbGRQYXRoIjoibWV0YWRhdGEubmFtZXNwYWNlIn19fV0sImltYWdlIjoiZG9ja2VyLmlvL2t1YmVzaGFyay93b3JrZXI6djUyLjEuNzUiLCJpbWFnZVB1bGxQb2xpY3kiOiJBbHdheXMiLCJuYW1lIjoidHJhY2VyIiwicmVzb3VyY2VzIjp7ImxpbWl0cyI6eyJjcHUiOiI3NTBtIiwibWVtb3J5IjoiMUdpIn0sInJlcXVlc3RzIjp7ImNwdSI6IjUwbSIsIm1lbW9yeSI6IjUwTWkifX0sInNlY3VyaXR5Q29udGV4dCI6eyJjYXBhYmlsaXRpZXMiOnsiYWRkIjpbIlNZU19BRE1JTiIsIlNZU19QVFJBQ0UiLCJTWVNfUkVTT1VSQ0UiLCJJUENfTE9DSyJdLCJkcm9wIjpbIkFMTCJdfX0sInRlcm1pbmF0aW9uTWVzc2FnZVBhdGgiOiIvZGV2L3Rlcm1pbmF0aW9uLWxvZyIsInRlcm1pbmF0aW9uTWVzc2FnZVBvbGljeSI6IkZpbGUiLCJ2b2x1bWVNb3VudHMiOlt7Im1vdW50UGF0aCI6Ii9ob3N0cHJvYyIsIm5hbWUiOiJwcm9jIiwicmVhZE9ubHkiOnRydWV9LHsibW91bnRQYXRoIjoiL3N5cyIsIm5hbWUiOiJzeXMiLCJyZWFkT25seSI6dHJ1ZX0seyJtb3VudFBhdGgiOiIvYXBwL2RhdGEiLCJuYW1lIjoiZGF0YSJ9LHsibW91bnRQYXRoIjoiL3Zhci9ydW4vc2VjcmV0cy9rdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50IiwibmFtZSI6Imt1YmUtYXBpLWFjY2Vzcy1zenBzbSIsInJlYWRPbmx5Ijp0cnVlfV19XSwiZG5zUG9saWN5IjoiQ2x1c3RlckZpcnN0V2l0aEhvc3ROZXQiLCJlbmFibGVTZXJ2aWNlTGlua3MiOnRydWUsImhvc3ROZXR3b3JrIjp0cnVlLCJpbml0Q29udGFpbmVycyI6W3siaW1hZ2UiOiJrdWJlc2hhcmsvcGYtcmluZy1tb2R1bGU6YWxsIiwiaW1hZ2VQdWxsUG9saWN5IjoiQWx3YXlzIiwibmFtZSI6ImxvYWQtcGYtcmluZyIsInJlc291cmNlcyI6eyJsaW1pdHMiOnt9LCJyZXF1ZXN0cyI6e319LCJzZWN1cml0eUNvbnRleHQiOnsiY2FwYWJpbGl0aWVzIjp7ImFkZCI6WyJTWVNfTU9EVUxFIl0sImRyb3AiOlsiQUxMIl19fSwidGVybWluYXRpb25NZXNzYWdlUGF0aCI6Ii9kZXYvdGVybWluYXRpb24tbG9nIiwidGVybWluYXRpb25NZXNzYWdlUG9saWN5IjoiRmlsZSIsInZvbHVtZU1vdW50cyI6W3sibW91bnRQYXRoIjoiL2xpYi9tb2R1bGVzIiwibmFtZSI6ImxpYi1tb2R1bGVzIn0seyJtb3VudFBhdGgiOiIvdmFyL3J1bi9zZWNyZXRzL2t1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQiLCJuYW1lIjoia3ViZS1hcGktYWNjZXNzLXN6cHNtIiwicmVhZE9ubHkiOnRydWV9XX1dLCJub2RlTmFtZSI6Im5vZGUtMSIsIm5vZGVTZWxlY3RvciI6e30sIm92ZXJoZWFkIjp7fSwicHJlZW1wdGlvblBvbGljeSI6IlByZWVtcHRMb3dlclByaW9yaXR5IiwicHJpb3JpdHkiOjAsInJlc3RhcnRQb2xpY3kiOiJBbHdheXMiLCJzY2hlZHVsZXJOYW1lIjoiZGVmYXVsdC1zY2hlZHVsZXIiLCJzZWN1cml0eUNvbnRleHQiOnt9LCJzZXJ2aWNlQWNjb3VudCI6Imt1YmVzaGFyay1zZXJ2aWNlLWFjY291bnQiLCJzZXJ2aWNlQWNjb3VudE5hbWUiOiJrdWJlc2hhcmstc2VydmljZS1hY2NvdW50IiwidGVybWluYXRpb25HcmFjZVBlcmlvZFNlY29uZHMiOjAsInRvbGVyYXRpb25zIjpbeyJlZmZlY3QiOiJOb0V4ZWN1dGUiLCJvcGVyYXRvciI6IkV4aXN0cyJ9LHsiZWZmZWN0IjoiTm9TY2hlZHVsZSIsIm9wZXJhdG9yIjoiRXhpc3RzIn0seyJlZmZlY3QiOiJOb0V4ZWN1dGUiLCJrZXkiOiJub2RlLmt1YmVybmV0ZXMuaW8vbm90LXJlYWR5Iiwib3BlcmF0b3IiOiJFeGlzdHMifSx7ImVmZmVjdCI6Ik5vRXhlY3V0ZSIsImtleSI6Im5vZGUua3ViZXJuZXRlcy5pby91bnJlYWNoYWJsZSIsIm9wZXJhdG9yIjoiRXhpc3RzIn0seyJlZmZlY3QiOiJOb1NjaGVkdWxlIiwia2V5Ijoibm9kZS5rdWJlcm5ldGVzLmlvL2Rpc2stcHJlc3N1cmUiLCJvcGVyYXRvciI6IkV4aXN0cyJ9LHsiZWZmZWN0IjoiTm9TY2hlZHVsZSIsImtleSI6Im5vZGUua3ViZXJuZXRlcy5pby9tZW1vcnktcHJlc3N1cmUiLCJvcGVyYXRvciI6IkV4aXN0cyJ9LHsiZWZmZWN0IjoiTm9TY2hlZHVsZSIsImtleSI6Im5vZGUua3ViZXJuZXRlcy5pby9waWQtcHJlc3N1cmUiLCJvcGVyYXRvciI6IkV4aXN0cyJ9LHsiZWZmZWN0IjoiTm9TY2hlZHVsZSIsImtleSI6Im5vZGUua3ViZXJuZXRlcy5pby91bnNjaGVkdWxhYmxlIiwib3BlcmF0b3IiOiJFeGlzdHMifSx7ImVmZmVjdCI6Ik5vU2NoZWR1bGUiLCJrZXkiOiJub2RlLmt1YmVybmV0ZXMuaW8vbmV0d29yay11bmF2YWlsYWJsZSIsIm9wZXJhdG9yIjoiRXhpc3RzIn1dLCJ2b2x1bWVzIjpbeyJob3N0UGF0aCI6eyJwYXRoIjoiL3Byb2MiLCJ0eXBlIjoiIn0sIm5hbWUiOiJwcm9jIn0seyJob3N0UGF0aCI6eyJwYXRoIjoiL3N5cyIsInR5cGUiOiIifSwibmFtZSI6InN5cyJ9LHsiaG9zdFBhdGgiOnsicGF0aCI6Ii9saWIvbW9kdWxlcyIsInR5cGUiOiIifSwibmFtZSI6ImxpYi1tb2R1bGVzIn0seyJlbXB0eURpciI6eyJzaXplTGltaXQiOiI1MDBNaSJ9LCJuYW1lIjoiZGF0YSJ9LHsibmFtZSI6Imt1YmUtYXBpLWFjY2Vzcy1zenBzbSIsInByb2plY3RlZCI6eyJkZWZhdWx0TW9kZSI6NDIwLCJzb3VyY2VzIjpbeyJzZXJ2aWNlQWNjb3VudFRva2VuIjp7ImV4cGlyYXRpb25TZWNvbmRzIjozNjA3LCJwYXRoIjoidG9rZW4ifX0seyJjb25maWdNYXAiOnsiaXRlbXMiOlt7ImtleSI6ImNhLmNydCIsInBhdGgiOiJjYS5jcnQifV0sIm5hbWUiOiJrdWJlLXJvb3QtY2EuY3J0In19LHsiZG93bndhcmRBUEkiOnsiaXRlbXMiOlt7ImZpZWxkUmVmIjp7ImFwaVZlcnNpb24iOiJ2MSIsImZpZWxkUGF0aCI6Im1ldGFkYXRhLm5hbWVzcGFjZSJ9LCJwYXRoIjoibmFtZXNwYWNlIn1dfX1dfX1dfSwic3RhdHVzIjp7ImNvbmRpdGlvbnMiOlt7Imxhc3RUcmFuc2l0aW9uVGltZSI6IjIwMjQtMDMtMjNUMDg6MTQ6NTkuMDAwMDAwWiIsInN0YXR1cyI6IlRydWUiLCJ0eXBlIjoiSW5pdGlhbGl6ZWQifSx7Imxhc3RUcmFuc2l0aW9uVGltZSI6IjIwMjQtMDMtMjNUMDg6MTU6MDkuMDAwMDAwWiIsInN0YXR1cyI6IlRydWUiLCJ0eXBlIjoiUmVhZHkifSx7Imxhc3RUcmFuc2l0aW9uVGltZSI6IjIwMjQtMDMtMjNUMDg6MTU6MDkuMDAwMDAwWiIsInN0YXR1cyI6IlRydWUiLCJ0eXBlIjoiQ29udGFpbmVyc1JlYWR5In0seyJsYXN0VHJhbnNpdGlvblRpbWUiOiIyMDI0LTAzLTIzVDA4OjE0OjUzLjAwMDAwMFoiLCJzdGF0dXMiOiJUcnVlIiwidHlwZSI6IlBvZFNjaGVkdWxlZCJ9XSwiY29udGFpbmVyU3RhdHVzZXMiOlt7ImFsbG9jYXRlZFJlc291cmNlcyI6e30sImNvbnRhaW5lcklEIjoiZG9ja2VyOi8vYmI1YWYzY2ZhYjBhZWZhYzk4Mzk4MDExZmFhNGQ0ZWU5MjljMWIyZGMxYzRhNDVlNTA4MjMxNWQ5OGVmYTYwMyIsImltYWdlIjoia3ViZXNoYXJrL3dvcmtlcjp2NTIuMS43NSIsImltYWdlSUQiOiJkb2NrZXItcHVsbGFibGU6Ly9rdWJlc2hhcmsvd29ya2VyQHNoYTI1NjpkODJmYTI1YmU2ZDg4NTM0ZWQ0ZjY4Nzc3MmQyZDZkYmViYzViNjgxN2M5ZDFkMDRhYWJjZTE4YWJlMDc2ZWNmIiwibGFzdFN0YXRlIjp7fSwibmFtZSI6InNuaWZmZXIiLCJyZWFkeSI6dHJ1ZSwicmVzdGFydENvdW50IjowLCJzdGFydGVkIjp0cnVlLCJzdGF0ZSI6eyJydW5uaW5nIjp7InN0YXJ0ZWRBdCI6IjIwMjQtMDMtMjNUMDg6MTU6MDQuMDAwMDAwWiJ9fX0seyJhbGxvY2F0ZWRSZXNvdXJjZXMiOnt9LCJjb250YWluZXJJRCI6ImRvY2tlcjovL2EwMDFiZjMxOWJjNzQ2MzdkN2JkMmI1MzI5ZTYyZTAxMzYyZjU1OTM4ODEyMDUyZjA3ZTcxMzZmYTc4ZTk0NTciLCJpbWFnZSI6Imt1YmVzaGFyay93b3JrZXI6djUyLjEuNzUiLCJpbWFnZUlEIjoiZG9ja2VyLXB1bGxhYmxlOi8va3ViZXNoYXJrL3dvcmtlckBzaGEyNTY6ZDgyZmEyNWJlNmQ4ODUzNGVkNGY2ODc3NzJkMmQ2ZGJlYmM1YjY4MTdjOWQxZDA0YWFiY2UxOGFiZTA3NmVjZiIsImxhc3RTdGF0ZSI6e30sIm5hbWUiOiJ0cmFjZXIiLCJyZWFkeSI6dHJ1ZSwicmVzdGFydENvdW50IjowLCJzdGFydGVkIjp0cnVlLCJzdGF0ZSI6eyJydW5uaW5nIjp7InN0YXJ0ZWRBdCI6IjIwMjQtMDMtMjNUMDg6MTU6MDguMDAwMDAwWiJ9fX1dLCJob3N0SVAiOiIxOTIuMTY4LjExNy41MSIsImluaXRDb250YWluZXJTdGF0dXNlcyI6W3siYWxsb2NhdGVkUmVzb3VyY2VzIjp7fSwiY29udGFpbmVySUQiOiJkb2NrZXI6Ly9mMzdmY2M5YjU3Y2YyN2ZlMmM2MjczZjc3ZjhlNjA5MjJlODUzMmRhNzVmZGQ1OThkZjMzZjJlNGU5ZWViY2U0IiwiaW1hZ2UiOiJrdWJlc2hhcmsvcGYtcmluZy1tb2R1bGU6YWxsIiwiaW1hZ2VJRCI6ImRvY2tlci1wdWxsYWJsZTovL2t1YmVzaGFyay9wZi1yaW5nLW1vZHVsZUBzaGEyNTY6NzE4ZDFlM2Q1MjZmOWFlODQyOTQ0ZDRmODVlODI2NGY3ZDMxOGIwMWEwOTkwM2NiOGYxZTQ3YmFlNmFhOWIwMyIsImxhc3RTdGF0ZSI6e30sIm5hbWUiOiJsb2FkLXBmLXJpbmciLCJyZWFkeSI6dHJ1ZSwicmVzdGFydENvdW50IjowLCJzdGFydGVkIjpmYWxzZSwic3RhdGUiOnsidGVybWluYXRlZCI6eyJjb250YWluZXJJRCI6ImRvY2tlcjovL2YzN2ZjYzliNTdjZjI3ZmUyYzYyNzNmNzdmOGU2MDkyMmU4NTMyZGE3NWZkZDU5OGRmMzNmMmU0ZTllZWJjZTQiLCJleGl0Q29kZSI6MCwiZmluaXNoZWRBdCI6IjIwMjQtMDMtMjNUMDg6MTQ6NTguMDAwMDAwWiIsInJlYXNvbiI6IkNvbXBsZXRlZCIsInN0YXJ0ZWRBdCI6IjIwMjQtMDMtMjNUMDg6MTQ6NTguMDAwMDAwWiJ9fX1dLCJwaGFzZSI6IlJ1bm5pbmciLCJwb2RJUCI6IjE5Mi4xNjguMTE3LjUxIiwicG9kSVBzIjpbeyJpcCI6IjE5Mi4xNjguMTE3LjUxIn1dLCJxb3NDbGFzcyI6IkJ1cnN0YWJsZSIsInN0YXJ0VGltZSI6IjIwMjQtMDMtMjNUMDg6MTQ6NTMuMDAwMDAwWiJ9fSx7Im1ldGFkYXRhIjp7ImFubm90YXRpb25zIjp7fSwiY3JlYXRpb25UaW1lc3RhbXAiOiIyMDI0LTAzLTIzVDA3OjMyOjUxLjAwMDAwMFoiLCJnZW5lcmF0ZU5hbWUiOiJrdWJlc2hhcmstd29ya2VyLWRhZW1vbi1zZXQtIiwibGFiZWxzIjp7ImFwcC5rdWJlcm5ldGVzLmlvL2luc3RhbmNlIjoia3ViZXNoYXJrIiwiYXBwLmt1YmVybmV0ZXMuaW8vbWFuYWdlZC1ieSI6IkhlbG0iLCJhcHAua3ViZXJuZXRlcy5pby9uYW1lIjoia3ViZXNoYXJrIiwiYXBwLmt1YmVybmV0ZXMuaW8vdmVyc2lvbiI6IjUyLjEuNzUiLCJhcHAua3ViZXNoYXJrLmNvL2FwcCI6IndvcmtlciIsImNvbnRyb2xsZXItcmV2aXNpb24taGFzaCI6IjlmZDhmN2M1NCIsImhlbG0uc2gvY2hhcnQiOiJrdWJlc2hhcmstNTIuMS43NSIsInBvZC10ZW1wbGF0ZS1nZW5lcmF0aW9uIjoiMSJ9LCJtYW5hZ2VkRmllbGRzIjpbeyJhcGlWZXJzaW9uIjoidjEiLCJmaWVsZHNUeXBlIjoiRmllbGRzVjEiLCJmaWVsZHNWMSI6eyJmOm1ldGFkYXRhIjp7ImY6Z2VuZXJhdGVOYW1lIjp7fSwiZjpsYWJlbHMiOnsiLiI6e30sImY6YXBwLmt1YmVybmV0ZXMuaW8vaW5zdGFuY2UiOnt9LCJmOmFwcC5rdWJlcm5ldGVzLmlvL21hbmFnZWQtYnkiOnt9LCJmOmFwcC5rdWJlcm5ldGVzLmlvL25hbWUiOnt9LCJmOmFwcC5rdWJlcm5ldGVzLmlvL3ZlcnNpb24iOnt9LCJmOmFwcC5rdWJlc2hhcmsuY28vYXBwIjp7fSwiZjpjb250cm9sbGVyLXJldmlzaW9uLWhhc2giOnt9LCJmOmhlbG0uc2gvY2hhcnQiOnt9LCJmOnBvZC10ZW1wbGF0ZS1nZW5lcmF0aW9uIjp7fX0sImY6b3duZXJSZWZlcmVuY2VzIjp7Ii4iOnt9LCJrOntcInVpZFwiOlwiMDVhZTMxZWEtZWRmOC00N2M2LTk5YWYtMGEyYzgxYjJjZWFlXCJ9Ijp7fX19LCJmOnNwZWMiOnsiZjphZmZpbml0eSI6eyIuIjp7fSwiZjpub2RlQWZmaW5pdHkiOnsiLiI6e30sImY6cmVxdWlyZWREdXJpbmdTY2hlZHVsaW5nSWdub3JlZER1cmluZ0V4ZWN1dGlvbiI6e319fSwiZjpjb250YWluZXJzIjp7Ims6e1wibmFtZVwiOlwic25pZmZlclwifSI6eyIuIjp7fSwiZjpjb21tYW5kIjp7fSwiZjplbnYiOnsiLiI6e30sIms6e1wibmFtZVwiOlwiS1VCRVNIQVJLX0NMT1VEX0FQSV9VUkxcIn0iOnsiLiI6e30sImY6bmFtZSI6e30sImY6dmFsdWUiOnt9fSwiazp7XCJuYW1lXCI6XCJQT0RfTkFNRVwifSI6eyIuIjp7fSwiZjpuYW1lIjp7fSwiZjp2YWx1ZUZyb20iOnsiLiI6e30sImY6ZmllbGRSZWYiOnt9fX0sIms6e1wibmFtZVwiOlwiUE9EX05BTUVTUEFDRVwifSI6eyIuIjp7fSwiZjpuYW1lIjp7fSwiZjp2YWx1ZUZyb20iOnsiLiI6e30sImY6ZmllbGRSZWYiOnt9fX0sIms6e1wibmFtZVwiOlwiVENQX1NUUkVBTV9DSEFOTkVMX1RJTUVPVVRfTVNcIn0iOnsiLiI6e30sImY6bmFtZSI6e30sImY6dmFsdWUiOnt9fX0sImY6aW1hZ2UiOnt9LCJmOmltYWdlUHVsbFBvbGljeSI6e30sImY6bGl2ZW5lc3NQcm9iZSI6eyIuIjp7fSwiZjpmYWlsdXJlVGhyZXNob2xkIjp7fSwiZjppbml0aWFsRGVsYXlTZWNvbmRzIjp7fSwiZjpwZXJpb2RTZWNvbmRzIjp7fSwiZjpzdWNjZXNzVGhyZXNob2xkIjp7fSwiZjp0Y3BTb2NrZXQiOnsiLiI6e30sImY6cG9ydCI6e319LCJmOnRpbWVvdXRTZWNvbmRzIjp7fX0sImY6bmFtZSI6e30sImY6cG9ydHMiOnsiLiI6e30sIms6e1wiY29udGFpbmVyUG9ydFwiOjQ5MTAwLFwicHJvdG9jb2xcIjpcIlRDUFwifSI6eyIuIjp7fSwiZjpjb250YWluZXJQb3J0Ijp7fSwiZjpob3N0UG9ydCI6e30sImY6bmFtZSI6e30sImY6cHJvdG9jb2wiOnt9fX0sImY6cmVhZGluZXNzUHJvYmUiOnsiLiI6e30sImY6ZmFpbHVyZVRocmVzaG9sZCI6e30sImY6aW5pdGlhbERlbGF5U2Vjb25kcyI6e30sImY6cGVyaW9kU2Vjb25kcyI6e30sImY6c3VjY2Vzc1RocmVzaG9sZCI6e30sImY6dGNwU29ja2V0Ijp7Ii4iOnt9LCJmOnBvcnQiOnt9fSwiZjp0aW1lb3V0U2Vjb25kcyI6e319LCJmOnJlc291cmNlcyI6eyIuIjp7fSwiZjpsaW1pdHMiOnsiLiI6e30sImY6Y3B1Ijp7fSwiZjptZW1vcnkiOnt9fSwiZjpyZXF1ZXN0cyI6eyIuIjp7fSwiZjpjcHUiOnt9LCJmOm1lbW9yeSI6e319fSwiZjpzZWN1cml0eUNvbnRleHQiOnsiLiI6e30sImY6Y2FwYWJpbGl0aWVzIjp7Ii4iOnt9LCJmOmFkZCI6e30sImY6ZHJvcCI6e319fSwiZjp0ZXJtaW5hdGlvbk1lc3NhZ2VQYXRoIjp7fSwiZjp0ZXJtaW5hdGlvbk1lc3NhZ2VQb2xpY3kiOnt9LCJmOnZvbHVtZU1vdW50cyI6eyIuIjp7fSwiazp7XCJtb3VudFBhdGhcIjpcIi9hcHAvZGF0YVwifSI6eyIuIjp7fSwiZjptb3VudFBhdGgiOnt9LCJmOm5hbWUiOnt9fSwiazp7XCJtb3VudFBhdGhcIjpcIi9ob3N0cHJvY1wifSI6eyIuIjp7fSwiZjptb3VudFBhdGgiOnt9LCJmOm5hbWUiOnt9LCJmOnJlYWRPbmx5Ijp7fX0sIms6e1wibW91bnRQYXRoXCI6XCIvc3lzXCJ9Ijp7Ii4iOnt9LCJmOm1vdW50UGF0aCI6e30sImY6bmFtZSI6e30sImY6cmVhZE9ubHkiOnt9fX19LCJrOntcIm5hbWVcIjpcInRyYWNlclwifSI6eyIuIjp7fSwiZjpjb21tYW5kIjp7fSwiZjplbnYiOnsiLiI6e30sIms6e1wibmFtZVwiOlwiUE9EX05BTUVcIn0iOnsiLiI6e30sImY6bmFtZSI6e30sImY6dmFsdWVGcm9tIjp7Ii4iOnt9LCJmOmZpZWxkUmVmIjp7fX19LCJrOntcIm5hbWVcIjpcIlBPRF9OQU1FU1BBQ0VcIn0iOnsiLiI6e30sImY6bmFtZSI6e30sImY6dmFsdWVGcm9tIjp7Ii4iOnt9LCJmOmZpZWxkUmVmIjp7fX19fSwiZjppbWFnZSI6e30sImY6aW1hZ2VQdWxsUG9saWN5Ijp7fSwiZjpuYW1lIjp7fSwiZjpyZXNvdXJjZXMiOnsiLiI6e30sImY6bGltaXRzIjp7Ii4iOnt9LCJmOmNwdSI6e30sImY6bWVtb3J5Ijp7fX0sImY6cmVxdWVzdHMiOnsiLiI6e30sImY6Y3B1Ijp7fSwiZjptZW1vcnkiOnt9fX0sImY6c2VjdXJpdHlDb250ZXh0Ijp7Ii4iOnt9LCJmOmNhcGFiaWxpdGllcyI6eyIuIjp7fSwiZjphZGQiOnt9LCJmOmRyb3AiOnt9fX0sImY6dGVybWluYXRpb25NZXNzYWdlUGF0aCI6e30sImY6dGVybWluYXRpb25NZXNzYWdlUG9saWN5Ijp7fSwiZjp2b2x1bWVNb3VudHMiOnsiLiI6e30sIms6e1wibW91bnRQYXRoXCI6XCIvYXBwL2RhdGFcIn0iOnsiLiI6e30sImY6bW91bnRQYXRoIjp7fSwiZjpuYW1lIjp7fX0sIms6e1wibW91bnRQYXRoXCI6XCIvaG9zdHByb2NcIn0iOnsiLiI6e30sImY6bW91bnRQYXRoIjp7fSwiZjpuYW1lIjp7fSwiZjpyZWFkT25seSI6e319LCJrOntcIm1vdW50UGF0aFwiOlwiL3N5c1wifSI6eyIuIjp7fSwiZjptb3VudFBhdGgiOnt9LCJmOm5hbWUiOnt9LCJmOnJlYWRPbmx5Ijp7fX19fX0sImY6ZG5zUG9saWN5Ijp7fSwiZjplbmFibGVTZXJ2aWNlTGlua3MiOnt9LCJmOmhvc3ROZXR3b3JrIjp7fSwiZjppbml0Q29udGFpbmVycyI6eyIuIjp7fSwiazp7XCJuYW1lXCI6XCJsb2FkLXBmLXJpbmdcIn0iOnsiLiI6e30sImY6aW1hZ2UiOnt9LCJmOmltYWdlUHVsbFBvbGljeSI6e30sImY6bmFtZSI6e30sImY6cmVzb3VyY2VzIjp7fSwiZjpzZWN1cml0eUNvbnRleHQiOnsiLiI6e30sImY6Y2FwYWJpbGl0aWVzIjp7Ii4iOnt9LCJmOmFkZCI6e30sImY6ZHJvcCI6e319fSwiZjp0ZXJtaW5hdGlvbk1lc3NhZ2VQYXRoIjp7fSwiZjp0ZXJtaW5hdGlvbk1lc3NhZ2VQb2xpY3kiOnt9LCJmOnZvbHVtZU1vdW50cyI6eyIuIjp7fSwiazp7XCJtb3VudFBhdGhcIjpcIi9saWIvbW9kdWxlc1wifSI6eyIuIjp7fSwiZjptb3VudFBhdGgiOnt9LCJmOm5hbWUiOnt9fX19fSwiZjpyZXN0YXJ0UG9saWN5Ijp7fSwiZjpzY2hlZHVsZXJOYW1lIjp7fSwiZjpzZWN1cml0eUNvbnRleHQiOnt9LCJmOnNlcnZpY2VBY2NvdW50Ijp7fSwiZjpzZXJ2aWNlQWNjb3VudE5hbWUiOnt9LCJmOnRlcm1pbmF0aW9uR3JhY2VQZXJpb2RTZWNvbmRzIjp7fSwiZjp0b2xlcmF0aW9ucyI6e30sImY6dm9sdW1lcyI6eyIuIjp7fSwiazp7XCJuYW1lXCI6XCJkYXRhXCJ9Ijp7Ii4iOnt9LCJmOmVtcHR5RGlyIjp7Ii4iOnt9LCJmOnNpemVMaW1pdCI6e319LCJmOm5hbWUiOnt9fSwiazp7XCJuYW1lXCI6XCJsaWItbW9kdWxlc1wifSI6eyIuIjp7fSwiZjpob3N0UGF0aCI6eyIuIjp7fSwiZjpwYXRoIjp7fSwiZjp0eXBlIjp7fX0sImY6bmFtZSI6e319LCJrOntcIm5hbWVcIjpcInByb2NcIn0iOnsiLiI6e30sImY6aG9zdFBhdGgiOnsiLiI6e30sImY6cGF0aCI6e30sImY6dHlwZSI6e319LCJmOm5hbWUiOnt9fSwiazp7XCJuYW1lXCI6XCJzeXNcIn0iOnsiLiI6e30sImY6aG9zdFBhdGgiOnsiLiI6e30sImY6cGF0aCI6e30sImY6dHlwZSI6e319LCJmOm5hbWUiOnt9fX19fSwibWFuYWdlciI6Imt1YmUtY29udHJvbGxlci1tYW5hZ2VyIiwib3BlcmF0aW9uIjoiVXBkYXRlIiwidGltZSI6IjIwMjQtMDMtMjNUMDc6MzI6NTEuMDAwMDAwWiJ9LHsiYXBpVmVyc2lvbiI6InYxIiwiZmllbGRzVHlwZSI6IkZpZWxkc1YxIiwiZmllbGRzVjEiOnsiZjpzdGF0dXMiOnsiZjpjb25kaXRpb25zIjp7Ims6e1widHlwZVwiOlwiQ29udGFpbmVyc1JlYWR5XCJ9Ijp7Ii4iOnt9LCJmOmxhc3RQcm9iZVRpbWUiOnt9LCJmOmxhc3RUcmFuc2l0aW9uVGltZSI6e30sImY6c3RhdHVzIjp7fSwiZjp0eXBlIjp7fX0sIms6e1widHlwZVwiOlwiSW5pdGlhbGl6ZWRcIn0iOnsiLiI6e30sImY6bGFzdFByb2JlVGltZSI6e30sImY6bGFzdFRyYW5zaXRpb25UaW1lIjp7fSwiZjpzdGF0dXMiOnt9LCJmOnR5cGUiOnt9fSwiazp7XCJ0eXBlXCI6XCJSZWFkeVwifSI6eyIuIjp7fSwiZjpsYXN0UHJvYmVUaW1lIjp7fSwiZjpsYXN0VHJhbnNpdGlvblRpbWUiOnt9LCJmOnN0YXR1cyI6e30sImY6dHlwZSI6e319fSwiZjpjb250YWluZXJTdGF0dXNlcyI6e30sImY6aG9zdElQIjp7fSwiZjppbml0Q29udGFpbmVyU3RhdHVzZXMiOnt9LCJmOnBoYXNlIjp7fSwiZjpwb2RJUCI6e30sImY6cG9kSVBzIjp7Ii4iOnt9LCJrOntcImlwXCI6XCIxOTIuMTY4LjExNy41MFwifSI6eyIuIjp7fSwiZjppcCI6e319fSwiZjpzdGFydFRpbWUiOnt9fX0sIm1hbmFnZXIiOiJrdWJlbGV0Iiwib3BlcmF0aW9uIjoiVXBkYXRlIiwic3VicmVzb3VyY2UiOiJzdGF0dXMiLCJ0aW1lIjoiMjAyNC0wMy0yM1QwNzozMzowNi4wMDAwMDBaIn1dLCJuYW1lIjoia3ViZXNoYXJrLXdvcmtlci1kYWVtb24tc2V0LXByem41IiwibmFtZXNwYWNlIjoiZGVmYXVsdCIsIm93bmVyUmVmZXJlbmNlcyI6W3siYXBpVmVyc2lvbiI6ImFwcHMvdjEiLCJibG9ja093bmVyRGVsZXRpb24iOnRydWUsImNvbnRyb2xsZXIiOnRydWUsImtpbmQiOiJEYWVtb25TZXQiLCJuYW1lIjoia3ViZXNoYXJrLXdvcmtlci1kYWVtb24tc2V0IiwidWlkIjoiMDVhZTMxZWEtZWRmOC00N2M2LTk5YWYtMGEyYzgxYjJjZWFlIn1dLCJyZXNvdXJjZVZlcnNpb24iOiIxOTQwNDEyIiwidWlkIjoiMjgyODBkYzEtMjk1Yi00YWU2LThkODEtYmIxOWRlY2I1NzdkIn0sInNwZWMiOnsiYWZmaW5pdHkiOnsibm9kZUFmZmluaXR5Ijp7InJlcXVpcmVkRHVyaW5nU2NoZWR1bGluZ0lnbm9yZWREdXJpbmdFeGVjdXRpb24iOnsibm9kZVNlbGVjdG9yVGVybXMiOlt7Im1hdGNoRmllbGRzIjpbeyJrZXkiOiJtZXRhZGF0YS5uYW1lIiwib3BlcmF0b3IiOiJJbiIsInZhbHVlcyI6WyJtYXN0ZXIiXX1dfV19fX0sImNvbnRhaW5lcnMiOlt7ImNvbW1hbmQiOlsiLi93b3JrZXIiLCItaSIsImFueSIsIi1wb3J0IiwiMzAwMDEiLCItbWV0cmljcy1wb3J0IiwiNDkxMDAiLCItdW5peHNvY2tldCIsIi1zZXJ2aWNlbWVzaCIsIi1wcm9jZnMiLCIvaG9zdHByb2MiLCIta2VybmVsLW1vZHVsZSJdLCJlbnYiOlt7Im5hbWUiOiJQT0RfTkFNRSIsInZhbHVlRnJvbSI6eyJmaWVsZFJlZiI6eyJhcGlWZXJzaW9uIjoidjEiLCJmaWVsZFBhdGgiOiJtZXRhZGF0YS5uYW1lIn19fSx7Im5hbWUiOiJQT0RfTkFNRVNQQUNFIiwidmFsdWVGcm9tIjp7ImZpZWxkUmVmIjp7ImFwaVZlcnNpb24iOiJ2MSIsImZpZWxkUGF0aCI6Im1ldGFkYXRhLm5hbWVzcGFjZSJ9fX0seyJuYW1lIjoiVENQX1NUUkVBTV9DSEFOTkVMX1RJTUVPVVRfTVMiLCJ2YWx1ZSI6IjEwMDAwIn0seyJuYW1lIjoiS1VCRVNIQVJLX0NMT1VEX0FQSV9VUkwiLCJ2YWx1ZSI6Imh0dHBzOi8vYXBpLmt1YmVzaGFyay5jbyJ9XSwiaW1hZ2UiOiJkb2NrZXIuaW8va3ViZXNoYXJrL3dvcmtlcjp2NTIuMS43NSIsImltYWdlUHVsbFBvbGljeSI6IkFsd2F5cyIsImxpdmVuZXNzUHJvYmUiOnsiZmFpbHVyZVRocmVzaG9sZCI6MywiaW5pdGlhbERlbGF5U2Vjb25kcyI6NSwicGVyaW9kU2Vjb25kcyI6MSwic3VjY2Vzc1RocmVzaG9sZCI6MSwidGNwU29ja2V0Ijp7InBvcnQiOjMwMDAxfSwidGltZW91dFNlY29uZHMiOjF9LCJuYW1lIjoic25pZmZlciIsInBvcnRzIjpbeyJjb250YWluZXJQb3J0Ijo0OTEwMCwiaG9zdFBvcnQiOjQ5MTAwLCJuYW1lIjoibWV0cmljcyIsInByb3RvY29sIjoiVENQIn1dLCJyZWFkaW5lc3NQcm9iZSI6eyJmYWlsdXJlVGhyZXNob2xkIjozLCJpbml0aWFsRGVsYXlTZWNvbmRzIjo1LCJwZXJpb2RTZWNvbmRzIjoxLCJzdWNjZXNzVGhyZXNob2xkIjoxLCJ0Y3BTb2NrZXQiOnsicG9ydCI6MzAwMDF9LCJ0aW1lb3V0U2Vjb25kcyI6MX0sInJlc291cmNlcyI6eyJsaW1pdHMiOnsiY3B1IjoiNzUwbSIsIm1lbW9yeSI6IjFHaSJ9LCJyZXF1ZXN0cyI6eyJjcHUiOiI1MG0iLCJtZW1vcnkiOiI1ME1pIn19LCJzZWN1cml0eUNvbnRleHQiOnsiY2FwYWJpbGl0aWVzIjp7ImFkZCI6WyJORVRfUkFXIiwiTkVUX0FETUlOIiwiU1lTX0FETUlOIiwiU1lTX1BUUkFDRSIsIkRBQ19PVkVSUklERSJdLCJkcm9wIjpbIkFMTCJdfX0sInRlcm1pbmF0aW9uTWVzc2FnZVBhdGgiOiIvZGV2L3Rlcm1pbmF0aW9uLWxvZyIsInRlcm1pbmF0aW9uTWVzc2FnZVBvbGljeSI6IkZpbGUiLCJ2b2x1bWVNb3VudHMiOlt7Im1vdW50UGF0aCI6Ii9ob3N0cHJvYyIsIm5hbWUiOiJwcm9jIiwicmVhZE9ubHkiOnRydWV9LHsibW91bnRQYXRoIjoiL3N5cyIsIm5hbWUiOiJzeXMiLCJyZWFkT25seSI6dHJ1ZX0seyJtb3VudFBhdGgiOiIvYXBwL2RhdGEiLCJuYW1lIjoiZGF0YSJ9LHsibW91bnRQYXRoIjoiL3Zhci9ydW4vc2VjcmV0cy9rdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50IiwibmFtZSI6Imt1YmUtYXBpLWFjY2Vzcy1kNHdybiIsInJlYWRPbmx5Ijp0cnVlfV19LHsiY29tbWFuZCI6WyIuL3RyYWNlciIsIi1wcm9jZnMiLCIvaG9zdHByb2MiXSwiZW52IjpbeyJuYW1lIjoiUE9EX05BTUUiLCJ2YWx1ZUZyb20iOnsiZmllbGRSZWYiOnsiYXBpVmVyc2lvbiI6InYxIiwiZmllbGRQYXRoIjoibWV0YWRhdGEubmFtZSJ9fX0seyJuYW1lIjoiUE9EX05BTUVTUEFDRSIsInZhbHVlRnJvbSI6eyJmaWVsZFJlZiI6eyJhcGlWZXJzaW9uIjoidjEiLCJmaWVsZFBhdGgiOiJtZXRhZGF0YS5uYW1lc3BhY2UifX19XSwiaW1hZ2UiOiJkb2NrZXIuaW8va3ViZXNoYXJrL3dvcmtlcjp2NTIuMS43NSIsImltYWdlUHVsbFBvbGljeSI6IkFsd2F5cyIsIm5hbWUiOiJ0cmFjZXIiLCJyZXNvdXJjZXMiOnsibGltaXRzIjp7ImNwdSI6Ijc1MG0iLCJtZW1vcnkiOiIxR2kifSwicmVxdWVzdHMiOnsiY3B1IjoiNTBtIiwibWVtb3J5IjoiNTBNaSJ9fSwic2VjdXJpdHlDb250ZXh0Ijp7ImNhcGFiaWxpdGllcyI6eyJhZGQiOlsiU1lTX0FETUlOIiwiU1lTX1BUUkFDRSIsIlNZU19SRVNPVVJDRSIsIklQQ19MT0NLIl0sImRyb3AiOlsiQUxMIl19fSwidGVybWluYXRpb25NZXNzYWdlUGF0aCI6Ii9kZXYvdGVybWluYXRpb24tbG9nIiwidGVybWluYXRpb25NZXNzYWdlUG9saWN5IjoiRmlsZSIsInZvbHVtZU1vdW50cyI6W3sibW91bnRQYXRoIjoiL2hvc3Rwcm9jIiwibmFtZSI6InByb2MiLCJyZWFkT25seSI6dHJ1ZX0seyJtb3VudFBhdGgiOiIvc3lzIiwibmFtZSI6InN5cyIsInJlYWRPbmx5Ijp0cnVlfSx7Im1vdW50UGF0aCI6Ii9hcHAvZGF0YSIsIm5hbWUiOiJkYXRhIn0seyJtb3VudFBhdGgiOiIvdmFyL3J1bi9zZWNyZXRzL2t1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQiLCJuYW1lIjoia3ViZS1hcGktYWNjZXNzLWQ0d3JuIiwicmVhZE9ubHkiOnRydWV9XX1dLCJkbnNQb2xpY3kiOiJDbHVzdGVyRmlyc3RXaXRoSG9zdE5ldCIsImVuYWJsZVNlcnZpY2VMaW5rcyI6dHJ1ZSwiaG9zdE5ldHdvcmsiOnRydWUsImluaXRDb250YWluZXJzIjpbeyJpbWFnZSI6Imt1YmVzaGFyay9wZi1yaW5nLW1vZHVsZTphbGwiLCJpbWFnZVB1bGxQb2xpY3kiOiJBbHdheXMiLCJuYW1lIjoibG9hZC1wZi1yaW5nIiwicmVzb3VyY2VzIjp7ImxpbWl0cyI6e30sInJlcXVlc3RzIjp7fX0sInNlY3VyaXR5Q29udGV4dCI6eyJjYXBhYmlsaXRpZXMiOnsiYWRkIjpbIlNZU19NT0RVTEUiXSwiZHJvcCI6WyJBTEwiXX19LCJ0ZXJtaW5hdGlvbk1lc3NhZ2VQYXRoIjoiL2Rldi90ZXJtaW5hdGlvbi1sb2ciLCJ0ZXJtaW5hdGlvbk1lc3NhZ2VQb2xpY3kiOiJGaWxlIiwidm9sdW1lTW91bnRzIjpbeyJtb3VudFBhdGgiOiIvbGliL21vZHVsZXMiLCJuYW1lIjoibGliLW1vZHVsZXMifSx7Im1vdW50UGF0aCI6Ii92YXIvcnVuL3NlY3JldHMva3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudCIsIm5hbWUiOiJrdWJlLWFwaS1hY2Nlc3MtZDR3cm4iLCJyZWFkT25seSI6dHJ1ZX1dfV0sIm5vZGVOYW1lIjoibWFzdGVyIiwibm9kZVNlbGVjdG9yIjp7fSwib3ZlcmhlYWQiOnt9LCJwcmVlbXB0aW9uUG9saWN5IjoiUHJlZW1wdExvd2VyUHJpb3JpdHkiLCJwcmlvcml0eSI6MCwicmVzdGFydFBvbGljeSI6IkFsd2F5cyIsInNjaGVkdWxlck5hbWUiOiJkZWZhdWx0LXNjaGVkdWxlciIsInNlY3VyaXR5Q29udGV4dCI6e30sInNlcnZpY2VBY2NvdW50Ijoia3ViZXNoYXJrLXNlcnZpY2UtYWNjb3VudCIsInNlcnZpY2VBY2NvdW50TmFtZSI6Imt1YmVzaGFyay1zZXJ2aWNlLWFjY291bnQiLCJ0ZXJtaW5hdGlvbkdyYWNlUGVyaW9kU2Vjb25kcyI6MCwidG9sZXJhdGlvbnMiOlt7ImVmZmVjdCI6Ik5vRXhlY3V0ZSIsIm9wZXJhdG9yIjoiRXhpc3RzIn0seyJlZmZlY3QiOiJOb1NjaGVkdWxlIiwib3BlcmF0b3IiOiJFeGlzdHMifSx7ImVmZmVjdCI6Ik5vRXhlY3V0ZSIsImtleSI6Im5vZGUua3ViZXJuZXRlcy5pby9ub3QtcmVhZHkiLCJvcGVyYXRvciI6IkV4aXN0cyJ9LHsiZWZmZWN0IjoiTm9FeGVjdXRlIiwia2V5Ijoibm9kZS5rdWJlcm5ldGVzLmlvL3VucmVhY2hhYmxlIiwib3BlcmF0b3IiOiJFeGlzdHMifSx7ImVmZmVjdCI6Ik5vU2NoZWR1bGUiLCJrZXkiOiJub2RlLmt1YmVybmV0ZXMuaW8vZGlzay1wcmVzc3VyZSIsIm9wZXJhdG9yIjoiRXhpc3RzIn0seyJlZmZlY3QiOiJOb1NjaGVkdWxlIiwia2V5Ijoibm9kZS5rdWJlcm5ldGVzLmlvL21lbW9yeS1wcmVzc3VyZSIsIm9wZXJhdG9yIjoiRXhpc3RzIn0seyJlZmZlY3QiOiJOb1NjaGVkdWxlIiwia2V5Ijoibm9kZS5rdWJlcm5ldGVzLmlvL3BpZC1wcmVzc3VyZSIsIm9wZXJhdG9yIjoiRXhpc3RzIn0seyJlZmZlY3QiOiJOb1NjaGVkdWxlIiwia2V5Ijoibm9kZS5rdWJlcm5ldGVzLmlvL3Vuc2NoZWR1bGFibGUiLCJvcGVyYXRvciI6IkV4aXN0cyJ9LHsiZWZmZWN0IjoiTm9TY2hlZHVsZSIsImtleSI6Im5vZGUua3ViZXJuZXRlcy5pby9uZXR3b3JrLXVuYXZhaWxhYmxlIiwib3BlcmF0b3IiOiJFeGlzdHMifV0sInZvbHVtZXMiOlt7Imhvc3RQYXRoIjp7InBhdGgiOiIvcHJvYyIsInR5cGUiOiIifSwibmFtZSI6InByb2MifSx7Imhvc3RQYXRoIjp7InBhdGgiOiIvc3lzIiwidHlwZSI6IiJ9LCJuYW1lIjoic3lzIn0seyJob3N0UGF0aCI6eyJwYXRoIjoiL2xpYi9tb2R1bGVzIiwidHlwZSI6IiJ9LCJuYW1lIjoibGliLW1vZHVsZXMifSx7ImVtcHR5RGlyIjp7InNpemVMaW1pdCI6IjUwME1pIn0sIm5hbWUiOiJkYXRhIn0seyJuYW1lIjoia3ViZS1hcGktYWNjZXNzLWQ0d3JuIiwicHJvamVjdGVkIjp7ImRlZmF1bHRNb2RlIjo0MjAsInNvdXJjZXMiOlt7InNlcnZpY2VBY2NvdW50VG9rZW4iOnsiZXhwaXJhdGlvblNlY29uZHMiOjM2MDcsInBhdGgiOiJ0b2tlbiJ9fSx7ImNvbmZpZ01hcCI6eyJpdGVtcyI6W3sia2V5IjoiY2EuY3J0IiwicGF0aCI6ImNhLmNydCJ9XSwibmFtZSI6Imt1YmUtcm9vdC1jYS5jcnQifX0seyJkb3dud2FyZEFQSSI6eyJpdGVtcyI6W3siZmllbGRSZWYiOnsiYXBpVmVyc2lvbiI6InYxIiwiZmllbGRQYXRoIjoibWV0YWRhdGEubmFtZXNwYWNlIn0sInBhdGgiOiJuYW1lc3BhY2UifV19fV19fV19LCJzdGF0dXMiOnsiY29uZGl0aW9ucyI6W3sibGFzdFRyYW5zaXRpb25UaW1lIjoiMjAyNC0wMy0yM1QwNzozMjo1Ni4wMDAwMDBaIiwic3RhdHVzIjoiVHJ1ZSIsInR5cGUiOiJJbml0aWFsaXplZCJ9LHsibGFzdFRyYW5zaXRpb25UaW1lIjoiMjAyNC0wMy0yM1QwNzozMzowNi4wMDAwMDBaIiwic3RhdHVzIjoiVHJ1ZSIsInR5cGUiOiJSZWFkeSJ9LHsibGFzdFRyYW5zaXRpb25UaW1lIjoiMjAyNC0wMy0yM1QwNzozMzowNi4wMDAwMDBaIiwic3RhdHVzIjoiVHJ1ZSIsInR5cGUiOiJDb250YWluZXJzUmVhZHkifSx7Imxhc3RUcmFuc2l0aW9uVGltZSI6IjIwMjQtMDMtMjNUMDc6MzI6NTEuMDAwMDAwWiIsInN0YXR1cyI6IlRydWUiLCJ0eXBlIjoiUG9kU2NoZWR1bGVkIn1dLCJjb250YWluZXJTdGF0dXNlcyI6W3siYWxsb2NhdGVkUmVzb3VyY2VzIjp7fSwiY29udGFpbmVySUQiOiJkb2NrZXI6Ly9mZjQ5NjMzMjAwNWZmN2ZmMjI0YzFkNjVmNzU5OWRhYWRkODVlYzQ5NTUzN2E3YzRhZGZjNGY2YTMwNDMyZWEwIiwiaW1hZ2UiOiJrdWJlc2hhcmsvd29ya2VyOnY1Mi4xLjc1IiwiaW1hZ2VJRCI6ImRvY2tlci1wdWxsYWJsZTovL2t1YmVzaGFyay93b3JrZXJAc2hhMjU2OmQ4MmZhMjViZTZkODg1MzRlZDRmNjg3NzcyZDJkNmRiZWJjNWI2ODE3YzlkMWQwNGFhYmNlMThhYmUwNzZlY2YiLCJsYXN0U3RhdGUiOnt9LCJuYW1lIjoic25pZmZlciIsInJlYWR5Ijp0cnVlLCJyZXN0YXJ0Q291bnQiOjAsInN0YXJ0ZWQiOnRydWUsInN0YXRlIjp7InJ1bm5pbmciOnsic3RhcnRlZEF0IjoiMjAyNC0wMy0yM1QwNzozMzowMC4wMDAwMDBaIn19fSx7ImFsbG9jYXRlZFJlc291cmNlcyI6e30sImNvbnRhaW5lcklEIjoiZG9ja2VyOi8vMTJmOWFlM2NmMzMyMGVmNjk0MTI4YjE2ZTgwYjI4NTAwOGViOTk0MTFlOTBiMDZkNWJkYjZlNzg5Mzk5OWRhMiIsImltYWdlIjoia3ViZXNoYXJrL3dvcmtlcjp2NTIuMS43NSIsImltYWdlSUQiOiJkb2NrZXItcHVsbGFibGU6Ly9rdWJlc2hhcmsvd29ya2VyQHNoYTI1NjpkODJmYTI1YmU2ZDg4NTM0ZWQ0ZjY4Nzc3MmQyZDZkYmViYzViNjgxN2M5ZDFkMDRhYWJjZTE4YWJlMDc2ZWNmIiwibGFzdFN0YXRlIjp7fSwibmFtZSI6InRyYWNlciIsInJlYWR5Ijp0cnVlLCJyZXN0YXJ0Q291bnQiOjAsInN0YXJ0ZWQiOnRydWUsInN0YXRlIjp7InJ1bm5pbmciOnsic3RhcnRlZEF0IjoiMjAyNC0wMy0yM1QwNzozMzowNS4wMDAwMDBaIn19fV0sImhvc3RJUCI6IjE5Mi4xNjguMTE3LjUwIiwiaW5pdENvbnRhaW5lclN0YXR1c2VzIjpbeyJhbGxvY2F0ZWRSZXNvdXJjZXMiOnt9LCJjb250YWluZXJJRCI6ImRvY2tlcjovLzBmODYzNDE2ODg0MTZjODZjMjA4MzU3MDUzMGY0YzU4ZDAzYzJlMmE2M2RiYTBkMTA0ZjZhMjU3OTI3ZWZiYTQiLCJpbWFnZSI6Imt1YmVzaGFyay9wZi1yaW5nLW1vZHVsZTphbGwiLCJpbWFnZUlEIjoiZG9ja2VyLXB1bGxhYmxlOi8va3ViZXNoYXJrL3BmLXJpbmctbW9kdWxlQHNoYTI1Njo3MThkMWUzZDUyNmY5YWU4NDI5NDRkNGY4NWU4MjY0ZjdkMzE4YjAxYTA5OTAzY2I4ZjFlNDdiYWU2YWE5YjAzIiwibGFzdFN0YXRlIjp7fSwibmFtZSI6ImxvYWQtcGYtcmluZyIsInJlYWR5Ijp0cnVlLCJyZXN0YXJ0Q291bnQiOjAsInN0YXJ0ZWQiOmZhbHNlLCJzdGF0ZSI6eyJ0ZXJtaW5hdGVkIjp7ImNvbnRhaW5lcklEIjoiZG9ja2VyOi8vMGY4NjM0MTY4ODQxNmM4NmMyMDgzNTcwNTMwZjRjNThkMDNjMmUyYTYzZGJhMGQxMDRmNmEyNTc5MjdlZmJhNCIsImV4aXRDb2RlIjowLCJmaW5pc2hlZEF0IjoiMjAyNC0wMy0yM1QwNzozMjo1Ni4wMDAwMDBaIiwicmVhc29uIjoiQ29tcGxldGVkIiwic3RhcnRlZEF0IjoiMjAyNC0wMy0yM1QwNzozMjo1Ni4wMDAwMDBaIn19fV0sInBoYXNlIjoiUnVubmluZyIsInBvZElQIjoiMTkyLjE2OC4xMTcuNTAiLCJwb2RJUHMiOlt7ImlwIjoiMTkyLjE2OC4xMTcuNTAifV0sInFvc0NsYXNzIjoiQnVyc3RhYmxlIiwic3RhcnRUaW1lIjoiMjAyNC0wMy0yM1QwNzozMjo1MS4wMDAwMDBaIn19XSwia2luZCI6IlBvZExpc3QiLCJtZXRhZGF0YSI6eyJyZXNvdXJjZVZlcnNpb24iOiIxOTQ3MDkxIn19";
        byte[] bytes = Base64Utils.decodeFromString(textStr);
        String s = new String(bytes);
        System.out.println(s);

    }


}

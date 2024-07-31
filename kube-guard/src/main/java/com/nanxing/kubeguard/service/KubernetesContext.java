package com.nanxing.kubeguard.service;

import com.nanxing.kubeguard.client.KubernetesClient;
import com.nanxing.kubeguard.entity.auth.ServiceAccount;
import com.nanxing.kubeguard.listener.KubernetesContextFlushEvent;
import io.kubernetes.client.openapi.models.V1Node;
import io.kubernetes.client.openapi.models.V1NodeAddress;
import io.kubernetes.client.openapi.models.V1Service;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;

/**
 * Author: Nanxing
 * Date: 2024/3/17 16:24
 */
@Component
@Slf4j
public class KubernetesContext implements ApplicationEventPublisherAware {

    @Autowired
    private KubernetesClient kubernetesClient;

    public List<ServiceAccount> serviceAccountList;

    public List<V1Service> v1ServiceList;

    public List<V1Node> v1NodeList;

    public List<String> nodeIpList;

    private ApplicationEventPublisher applicationEventPublisher;

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    @Scheduled(fixedRate = 300000)
    @PostConstruct
    public void flushServiceAccountList(){
        serviceAccountList = kubernetesClient.getAllServiceAccount();

        v1ServiceList = kubernetesClient.getAllServices();

        //v1NodeList = kubernetesClient.getAllNodes();

        nodeIpList = new ArrayList<>();
        nodeIpList.add("192.168.137.200");
        nodeIpList.add("192.168.117.51");
        //for (V1Node v1Node : v1NodeList) {
        //    List<V1NodeAddress> addresses = v1Node.getStatus().getAddresses();
        //    for (V1NodeAddress address : addresses) {
        //        if("InternalIP".equals(address.getType())){
        //            nodeIpList.add(address.getAddress());
        //        }
        //    }
        //}

        //发布刷新KubernetesContext事件
        this.applicationEventPublisher.publishEvent(new KubernetesContextFlushEvent(new Object()));
        log.info("Kubernetes context has been updated!");
    }


}

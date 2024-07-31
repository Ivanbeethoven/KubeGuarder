package com.nanxing.kubeguard.client;

import com.nanxing.kubeguard.entity.auth.ClusterRole;
import com.nanxing.kubeguard.entity.auth.Pod;
import com.nanxing.kubeguard.entity.auth.Role;
import com.nanxing.kubeguard.entity.auth.ServiceAccount;
import com.nanxing.kubeguard.utils.KubeTypeUtils;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.Configuration;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.apis.RbacAuthorizationV1Api;
import io.kubernetes.client.openapi.models.*;
import io.kubernetes.client.util.Config;
import org.apache.commons.lang3.StringUtils;
import org.mortbay.log.Log;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Author: Nanxing
 * Date: 2024/3/5 16:27
 */

public class KubernetesClient {

    public ApiClient apiClient;
    public KubernetesClient(ApiClient apiClient){
        this.apiClient = apiClient;
    }
    public List<ServiceAccount> getAllServiceAccount(){
        CoreV1Api coreV1Api = new CoreV1Api(apiClient);
        RbacAuthorizationV1Api rbacAuthorizationV1Api = new RbacAuthorizationV1Api(apiClient);

        try {
            V1ServiceAccountList v1ServiceAccountList = coreV1Api.listServiceAccountForAllNamespaces().execute();
            List<V1ServiceAccount> items = v1ServiceAccountList.getItems();
            //过滤掉系统服务账户
            List<V1ServiceAccount> filteredItems = items.stream().filter(v1ServiceAccount -> {
                String ns = v1ServiceAccount.getMetadata().getNamespace();
                return !(ns.equals("kube-public") || ns.equals("kube-system") || ns.equals("kube-node-lease") || ns.equals("kube-flannel") || ns.equals("kube-guard"));
            }).collect(Collectors.toList());

            //转化为ServiceAccount
            List<ServiceAccount> serviceAccountList = filteredItems.stream().map(v1ServiceAccount -> {
                ServiceAccount serviceAccount = new ServiceAccount();
                serviceAccount.setApiVersion(v1ServiceAccount.getApiVersion());
                serviceAccount.setNamespace(v1ServiceAccount.getMetadata().getNamespace());
                serviceAccount.setName(v1ServiceAccount.getMetadata().getName());
                return serviceAccount;
            }).collect(Collectors.toList());

            //获取所有的Role、ClusterRole、RoleBinding 和 ClusterRoleBinding
            V1ClusterRoleList v1ClusterRoleList = rbacAuthorizationV1Api.listClusterRole().execute();
            V1ClusterRoleBindingList v1ClusterRoleBindingList = rbacAuthorizationV1Api.listClusterRoleBinding().execute();
            V1RoleList v1RoleList = rbacAuthorizationV1Api.listRoleForAllNamespaces().execute();
            V1RoleBindingList v1RoleBindingList = rbacAuthorizationV1Api.listRoleBindingForAllNamespaces().execute();


            for (ServiceAccount serviceAccount : serviceAccountList) {
                String namespace = serviceAccount.getNamespace();
                String serviceAccountName = serviceAccount.getName();

                List<Role> roleList = new ArrayList<>();
                List<ClusterRole> clusterRoleList = new ArrayList<>();
                serviceAccount.setRoleList(roleList);
                serviceAccount.setClusterRoleList(clusterRoleList);

                //获取该服务账户绑定的roles
                for (V1RoleBinding item : v1RoleBindingList.getItems()) {
                    List<V1Subject> v1Subjects = item.getSubjects();
                    //v1Subjects.stream().forEach(subject->System.out.println(subject.toString()) );
                    if(v1Subjects.stream()
                            .anyMatch((v1Subject) -> // v1Subject may be null???
                                {   
                                    String a = v1Subject.getKind();
                                    String b = v1Subject.getName();
                                    String c = v1Subject.getNamespace();
                                    if (a==null || b==null || c==null){
                                        return false;
                                    }
                                    boolean d = a.equals("ServiceAccount");
                                    boolean e = b.equals(serviceAccountName);
                                    boolean f = c.equals(namespace);
                                    return  d && e && f;
                                }

                            )){
                        String kind = item.getRoleRef().getKind();
                        String roleName = item.getRoleRef().getName();
                        String roleNamespace = item.getMetadata().getNamespace();
                        //如果绑定的是Role
                        if("Role".equals(kind)){
                            Optional<V1Role> optionalV1Role = v1RoleList.getItems()
                                    .stream()
                                    .filter(v1Role -> v1Role.getMetadata().getName().equals(roleName) && v1Role.getMetadata().getNamespace().equals(roleNamespace))
                                    .findFirst();
                            if(optionalV1Role.isPresent()){
                                V1Role v1Role = optionalV1Role.get();
                                Role role = KubeTypeUtils.v1Role2Role(v1Role);
                                roleList.add(role);
                            }
                        }
                        //如果绑定的是ClusterRole
                        if("ClusterRole".equals(kind)){
                            Optional<V1ClusterRole> optionalV1ClusterRole = v1ClusterRoleList.getItems()
                                    .stream()
                                    .filter(v1ClusterRole -> v1ClusterRole.getMetadata().getName().equals(roleName))
                                    .findFirst();
                            if(optionalV1ClusterRole.isPresent()){
                                V1ClusterRole v1ClusterRole = optionalV1ClusterRole.get();
                                Role role = KubeTypeUtils.v1ClusterRole2Role(v1ClusterRole, namespace);
                                roleList.add(role);
                            }
                        }

                    }
                }

                //获取该服务账户绑定的ClusterRole
                for (V1ClusterRoleBinding item : v1ClusterRoleBindingList.getItems()) {

                    //System.out.println(item.toJson());
                    List<V1Subject> v1Subjects = item.getSubjects();
                    if(v1Subjects == null)
                        continue;
                    if(v1Subjects.stream()
                            .anyMatch(v1Subject -> v1Subject.getKind().equals("ServiceAccount")
                                    && v1Subject.getName().equals(serviceAccountName)
                                    && v1Subject.getNamespace().equals(namespace))){
                        String clusterRoleName = item.getRoleRef().getName();
                        Optional<V1ClusterRole> optionalV1ClusterRole = v1ClusterRoleList.getItems()
                                .stream()
                                .filter(v1ClusterRole -> v1ClusterRole.getMetadata().getName().equals(clusterRoleName))
                                .findFirst();
                        if(optionalV1ClusterRole.isPresent()){
                            V1ClusterRole v1ClusterRole = optionalV1ClusterRole.get();
                            ClusterRole clusterRole = KubeTypeUtils.v1ClusterRole2ClusterRole(v1ClusterRole);
                            clusterRoleList.add(clusterRole);
                        }
                    }
                }

                V1PodList v1PodList = coreV1Api.listNamespacedPod(namespace).execute();
                List<Pod> podList = v1PodList.getItems()
                        .stream()
                        .filter(v1Pod -> {
                            String accountName = v1Pod.getSpec().getServiceAccountName();
                            if (accountName == null || accountName.isEmpty()) {
                                return serviceAccountName.equals("default");
                            }
                            return accountName.equals(serviceAccountName);
                        }).map(v1Pod -> {
                            Pod pod = new Pod();
                            pod.setName(v1Pod.getMetadata().getName());
                            pod.setNamespace(v1Pod.getMetadata().getNamespace());
                            pod.setServiceAccountName(serviceAccountName);
                            pod.setIp(v1Pod.getStatus().getPodIP());
                            pod.setLabels(v1Pod.getMetadata().getLabels());
                            return pod;
                        }).collect(Collectors.toList());
                serviceAccount.setPodList(podList);
            }
            return serviceAccountList;

            //for (V1ServiceAccount v1ServiceAccount : filteredItems) {
            //    System.out.println(v1ServiceAccount.getMetadata().getNamespace() + ":" +v1ServiceAccount.getMetadata().getName());
            //}
        } catch (ApiException e) {
            e.printStackTrace();
        }
        return null;
    }

    public List<V1Pod> getAllPods(){
        CoreV1Api coreV1Api = new CoreV1Api(apiClient);
        try {
            V1PodList v1PodList = coreV1Api.listPodForAllNamespaces().execute();
            return v1PodList.getItems();
        } catch (ApiException e) {
            e.printStackTrace();
        }
        return null;
    }

    public Role getOneRole(String namespace, String name){
        RbacAuthorizationV1Api rbacAuthorizationV1Api = new RbacAuthorizationV1Api(apiClient);
        try {
            V1Role v1Role = rbacAuthorizationV1Api.readNamespacedRole(name, namespace).execute();
            return KubeTypeUtils.v1Role2Role(v1Role);
        } catch (ApiException e) {
            e.printStackTrace();
            return null;
        }
    }

    public ClusterRole getOneClusterRole(String name){
        RbacAuthorizationV1Api rbacAuthorizationV1Api = new RbacAuthorizationV1Api(apiClient);
        try {
            V1ClusterRole v1ClusterRole = rbacAuthorizationV1Api.readClusterRole(name).execute();
            return KubeTypeUtils.v1ClusterRole2ClusterRole(v1ClusterRole);
        } catch (ApiException e) {
            e.printStackTrace();
            return null;
        }
    }

    public List<V1Service> getAllServices(){
        CoreV1Api coreV1Api = new CoreV1Api();
        try {
            V1ServiceList v1ServiceList = coreV1Api.listServiceForAllNamespaces().execute();
            return v1ServiceList.getItems();
        } catch (ApiException e) {
            e.printStackTrace();
            return null;
        }
    }

    public List<V1Node> getAllNodes(){
        CoreV1Api coreV1Api = new CoreV1Api();
        V1NodeList v1NodeList = null;
        try {
            v1NodeList = coreV1Api.listNode().execute();
            return v1NodeList.getItems();
        } catch (ApiException e) {
            e.printStackTrace();
            return null;
        }
    }



    public static void main(String[] args) {
        // 设置访问令牌
        String token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik84Y3JlX3VDNlN3N0NYMlFZeGxmYjRPZGlCRFFKXzhuUFdnYml3bDNSSkEifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImFkbWluLXNlcnZpY2VhY2NvdW50LXRva2VuMSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJhZG1pbi1zZXJ2aWNlYWNjb3VudCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjFiYzAwNzUwLTM5N2YtNDI0My04ZTQzLTQ4M2M2M2UyOTc1YiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmFkbWluLXNlcnZpY2VhY2NvdW50In0.0LN6wM6SvEkG5oIjT9W5AFJmK4KAbOJbEWHeE0QfGIo4sdcByvzT6mGMcfBlDEsmVkTWtbrz4XdyjmYbmQ-DWhzbLWKU8BmRP34f9YHqflx-OAVGXiUZXSeZ8c0JPJgO6jc4mDqxFHt0-D12BH0X8pI-url4zDzau3hN2PR7dHhxSiYW85ABw60HRDp2qIJWwZoABBwHEQkZQ0pnVfpEu39BoVmQzMVn0Gp_cJ1f98gdjjJ57hFkPklJWgnLWVJUJha2pMTpgCLPShw5BDbjVkJkE8Tpf21wo_LfppO_rOG4kx4HFSBbI_vsAfatzce5-logCkzdGPppryQ3j8bQrw";
        // 创建 ApiClient 实例并设置访问令牌
        ApiClient client = Config.fromToken("https://192.168.137.200:6443", token, false);

        KubernetesClient kubernetesClient = new KubernetesClient(client);


        List<ServiceAccount> allServiceAccount = kubernetesClient.getAllServiceAccount();
        for (ServiceAccount serviceAccount : allServiceAccount) {
            System.out.println(serviceAccount.getName());
        }

        //List<V1Pod> v1PodList = kubernetesClient.getAllPods();
        //for (V1Pod v1Pod : v1PodList) {
        //    v1Pod.getSpec().getServiceAccount();
        //}
    }
}

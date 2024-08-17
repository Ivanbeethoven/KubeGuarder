import requests
from kubernetes import client, config
import warnings
import json
import yaml

class KubernetesClient:
    def __init__(self, config_file):
        config.load_kube_config(config_file=config_file)
    
    #获取所有命名空间
    def get_all_namespaces(self):
        v1 = client.CoreV1Api()
        namespace_item_list = v1.list_namespace().items
        namespace_list = [namespace.metadata.name for namespace in namespace_item_list]
        return namespace_list

    # 获取所有服务账户，返回一个字典，key：命名空间:账户名 value：账户资源清单
    def get_all_serviceaccounts(self):
        v1 = client.CoreV1Api()
        response = v1.list_service_account_for_all_namespaces()
        sa_list = response.items
        api_version = response.api_version
        sa_dict = {}
        for sa in sa_list:
            namespace = sa.metadata.namespace
            if namespace in ['kube-system','kube-node-lease','kube-public']:
                continue
            serial_sa = client.ApiClient().sanitize_for_serialization(sa) #转为可序列化的字典
            new_serial_sa = {}
            new_serial_sa['apiVersion'] = api_version
            new_serial_sa['kind'] = "ServiceAccount"
            for key, item in serial_sa.items():
                new_serial_sa[key] = item
            self.clear_data(new_serial_sa)
            key = f"{sa.metadata.namespace}/{sa.metadata.name}"
            sa_dict[key] = new_serial_sa
        return sa_dict

    # 获取所有服务账户,携带权限规则
    # 返回一个字典，key：命名空间:账户名 value：账户资源清单(带rule)
    def get_all_service_account_with_rules(self):
        #获取所有的服务账户
        sa_dict = self.get_all_serviceaccounts()
        rbac_client = client.RbacAuthorizationV1Api()
        #获取所有clusterrolebinding和clusterrole
        cluster_role_binding_list = rbac_client.list_cluster_role_binding().items
        cluster_role_list = rbac_client.list_cluster_role().items
        #获取所有rolebinding和role
        all_role_binding_list = rbac_client.list_role_binding_for_all_namespaces().items
        all_role_list = rbac_client.list_role_for_all_namespaces().items

        #将所有rolebinding和role按命名空间划分
        ns_role_binding_dict = {} #key:命名空间  value: rolebinding数组
        ns_role_dict = {} #key:命名空间 value: role数组
        for role_binding in all_role_binding_list:
            role_binding_namespace = role_binding.metadata.namespace
            if role_binding_namespace not in ns_role_binding_dict:
                ns_role_binding_dict[role_binding_namespace] = []
            ns_role_binding_dict[role_binding_namespace].append(role_binding)
        for role in all_role_list:
            role_namespace = role.metadata.namespace
            if role_namespace not in ns_role_dict:
                ns_role_dict[role_namespace] = []
            ns_role_dict[role_namespace].append(role)
   
        # #对于每个服务账户
        for sa_key in sa_dict.keys():
            sa = sa_dict[sa_key]
            sa_namespace = sa["metadata"]["namespace"]
            sa_name = sa["metadata"]["name"]
            #获取命名空间范围的rule
            ns_role_binding_list = []
            if sa_namespace in ns_role_binding_dict:
                ns_role_binding_list = ns_role_binding_dict[sa_namespace]
            
            ns_role_list = []
            if sa_namespace in ns_role_dict:
                ns_role_list = ns_role_dict[sa_namespace]

            sa_rule_list = []
            
            for role_binding in ns_role_binding_list:
                #判断该role_binding是否绑定了该服务账户
                flag = False
                subject_list = role_binding.subjects
                for subject in subject_list:
                    if subject.kind == "ServiceAccount" and subject.name == sa_name:
                        flag = True
                        break
                    #如果绑定了该服务账户，则获取绑定的role并获取内部的规则
                if flag:
                    role_ref_kind = role_binding.role_ref.kind #获取角色类型
                    role_ref_name = role_binding.role_ref.name #获取角色名称

                    #需要找到所绑定的role或者clusterrole
                    if role_ref_kind == "Role":
                        for role in ns_role_list:
                            if role.metadata.name == role_ref_name:
                                sa_rule_list.extend(role.rules)
                                break
                    #K8S允许rolebinding绑定clusterrole，但权限作用域仍是命名空间内
                    elif role_ref_kind == "ClusterRole":
                        for cluster_role in cluster_role_list:
                            if role.metadata.name == role_ref_name:
                                sa_rule_list.extend(cluster_role.rules)
                                break
            sa['rule_list'] = [client.ApiClient().sanitize_for_serialization(rule) for rule in sa_rule_list]

            #获取全局范围的rule
            sa_cluster_rule_list = []
            for cluster_role_binding in cluster_role_binding_list:
                #判断该cluster_role_binding是否绑定了该服务账户
                flag = False
                subject_list = cluster_role_binding.subjects
                if subject_list is not None:
                    for subject in subject_list:
                        if subject.kind == "ServiceAccount" and subject.name == sa_name:
                            flag = True
                            break
                    #如果绑定了该服务账户，则获取绑定的cluster_role并获取内部的规则
                if flag:
                    role_ref_kind = cluster_role_binding.role_ref.kind #获取角色类型
                    role_ref_name = cluster_role_binding.role_ref.name #获取角色名称
                    if role_ref_kind == "ClusterRole":
                        for cluster_role in cluster_role_list:
                            if cluster_role.metadata.name == role_ref_name:
                                sa_cluster_rule_list.extend(cluster_role.rules)
                                break
            sa['cluster_rule_list'] = [client.ApiClient().sanitize_for_serialization(rule) for rule in sa_cluster_rule_list]
        return sa_dict
             
    #获取所有的资源对象，用字典存储
    def get_all_resource(self):
        all_resource_dict = {}
        #首先获取所有的命名空间
        namespace_list = self.get_all_namespaces()
        #获取当前K8S可用的资源组和每组的资源类别
        api_group_version_dict = self.get_api_versions_groups_and_kinds()
        #第一步，获取所有命名空间级别的资源
        for ns in namespace_list:
            all_resource_dict[ns] = self.get_all_resource_of_namespace(ns, api_group_version_dict=api_group_version_dict)
        #第二步，获取集群级别的资源
        all_resource_dict["cluster-level"] = self.get_all_cluster_level_resource(api_group_version_dict=api_group_version_dict)
        return all_resource_dict
    
    # 获取所有集群级别的资源
    def get_all_cluster_level_resource(self, api_group_version_dict):
        api_client = client.ApiClient()
        group_version_resource_dict = {}
        for group_version, kind_list in api_group_version_dict.items():
            path_prefix = "/apis"
            if group_version == "v1":
                path_prefix = "/api"
            for kind in kind_list:
                if(kind["namespaced"] is False and "list" in kind["verbs"]):
                    path = f"{path_prefix}/{group_version}/{kind['name']}"
                    #print(path)
                    response = api_client.call_api(path, 'GET', response_type='object')
                    resource_dict = api_client.sanitize_for_serialization(response[0])
                    resource_list = resource_dict["items"]
                    if resource_list is not None and len(resource_list) > 0:
                        new_resource_list = []
                        for resource in resource_list:
                            new_resource = {}
                            new_resource['kind'] = kind['kind']
                            new_resource['apiVersion'] = resource_dict['apiVersion']
                            for key, item in resource.items():
                                new_resource[key] = item
                            self.clear_data(new_resource)
                            new_resource_list.append(new_resource)
                        group_version_resource_dict[f"{group_version}/cluster-level/{kind['name']}"] =new_resource_list
            #print(group_version_resource_dict)
        return group_version_resource_dict
    
    # 获取指定命名空间内的 命名空间级别 的资源
    def get_all_resource_of_namespace(self, namespace, api_group_version_dict):
        api_client = client.ApiClient()
        group_version_resource_dict = {}
        for group_version, kind_list in api_group_version_dict.items():
            path_prefix = "/apis"
            if group_version == "v1":
                path_prefix = "/api"
            for kind in kind_list:
                if(kind["namespaced"] and "list" in kind["verbs"]):
                    
                    path = f"{path_prefix}/{group_version}/namespaces/{namespace}/{kind['name']}"
                    #print(path)
                    response = api_client.call_api(path, 'GET', response_type='object')
                    resource_dict = api_client.sanitize_for_serialization(response[0])
                    resource_list = resource_dict["items"]
                    if resource_list is not None and len(resource_list) > 0:
                        new_resource_list = []
                        for resource in resource_list:
                            new_resource = {}
                            new_resource['kind'] = kind['kind']
                            new_resource['apiVersion'] = resource_dict['apiVersion']
                            for key, item in resource.items():
                                new_resource[key] = item
                            self.clear_data(new_resource)
                            new_resource_list.append(new_resource)
                        group_version_resource_dict[f"{group_version}/{namespace}/{kind['name']}"] = new_resource_list
            #print(group_version_resource_dict)
        return group_version_resource_dict
    
    #获取当前K8S可用的资源组和每组的资源类别
    def get_api_versions_groups_and_kinds(self):
        api_groups = client.ApisApi().get_api_versions()
        api_client = client.ApiClient()
        api_groups_dict = api_client.sanitize_for_serialization(api_groups)
        api_group_version_dict = {}

        #首先获取核心组的资源
        api_group_version_dict["v1"] = []
        core_resources = api_client.call_api(f'/api/v1', 'GET', response_type='object')[0]
        core_resource_dict = api_client.sanitize_for_serialization(core_resources)
        for resource in core_resource_dict.get('resources', []):
            api_group_version_dict["v1"].append(resource)

        for group in api_groups_dict['groups']:
            for version in group.get('versions', []):
                group_version = version["groupVersion"]
                version_name = version['version']
                api_group_version_dict[group_version] = []
                # 获取该版本中的资源类别
                resources = api_client.call_api(f'/apis/{group_version}', 'GET', response_type='object')[0]
                resources_dict = api_client.sanitize_for_serialization(resources)
                for resource in resources_dict.get('resources', []):
                    api_group_version_dict[group_version].append(resource)
        return api_group_version_dict

    #清洗掉不需要的字段
    def clear_data(self, data_dict):
        if "metadata" in data_dict:
            metadata = data_dict["metadata"]
            if "managedFields" in metadata:
                del metadata["managedFields"]
            if "annotations" in metadata:
                if "kubectl.kubernetes.io/last-applied-configuration" in metadata["annotations"]:
                    del metadata["annotations"]["kubectl.kubernetes.io/last-applied-configuration"]


#测试输出
# kubernetesClient = KubernetesClient(config_file="config")
# resource_dict = kubernetesClient.get_all_resource()
# jsonstr = json.dumps(resource_dict, indent=2)
# with open("resource-file/all-resources.json", 'w') as file:
#      file.write(jsonstr)
# yaml_string = yaml.dump(api_group_dict, default_flow_style=False)
# print(yaml_string)
# 指定保存文件的路径
#file_path = 'api-groups.yaml'
# 将 YAML 字符串写入文件
# with open(file_path, 'w') as file:
#     file.write(yaml_string)
        

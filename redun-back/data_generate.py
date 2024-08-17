from kubernetes_client import KubernetesClient
import audit_log_utils
import json
import fnmatch
import os
import random

#生成训练样本
def generate_train_data():
    log_folder_path = 'audit-logs/logs1'
    permission_config_file = 'config'
    
    kubernetes_client = KubernetesClient(config_file=permission_config_file)
    service_account_dict = kubernetes_client.get_all_serviceaccounts()
    service_account_with_rule_dict = kubernetes_client.get_all_service_account_with_rules()
    all_resource_dict = kubernetes_client.get_all_resource()
    
    all_resource = {}
    #加工成一级索引的resource
    for ns, kind_key_dict in all_resource_dict.items():
        for kind_key, resource_list in kind_key_dict.items():
            for resource in resource_list:
                resource_key = f"{kind_key}/{resource['metadata']['name']}"
                all_resource[resource_key] = resource
                
    #获取所有资源的索引
    all_resource_key_list = all_resource.keys()
    
    print(len(all_resource_key_list))
    #正
    positive_data_dict = audit_log_utils.process_log_folder(log_folder_path)
    
    #负
    negative_data_dict = {}

    for sa_key, sa_with_rule in service_account_with_rule_dict.items():
        print(sa_key)
        #如果没有正例
        if sa_key not in positive_data_dict:
            continue
        positive_data_list = positive_data_dict[sa_key]
        
        #确定负样本生成数量，为正样本的两倍
        positive_data_num = len(positive_data_list)
        negative_data_num = positive_data_num
        
        sa = service_account_dict[sa_key]
        #获取该账户每种操作可以访问的资源
        available_resource_dict = get_available_resource_of_service_account(sa_with_rule) 
        
        ##获取每个动词对应的不可访问资源,
        unavailable_resource_key_dict = {}
        for verb, available_resource_key_list in available_resource_dict.items():
            available_resource_key_set = set()
            for res_key in available_resource_key_list:
                if res_key.startswith('[sub]'):
                    splited = res_key.split()
                    res_key = f"{splited[1]}/{splited[2]}"
                available_resource_key_set.add(res_key)
            unavailable_resource_key_list = [elem for elem in all_resource_key_list if elem not in available_resource_key_set]
            if unavailable_resource_key_list: #过滤掉为空的数组
                unavailable_resource_key_dict[verb] = unavailable_resource_key_list
        
        #如果服务账户拥有所有权限，那么该dict为空
        if not unavailable_resource_key_dict:
            print(f"{sa_key} 不存在不可访问资源")
            break
        verb_list = list(unavailable_resource_key_dict.keys())
        
        #构建负样本
        negative_data_list = []
        for _ in range(negative_data_num):
            #随机挑选一个动词
            verb = random.choice(verb_list)
            unavailable_resource_key_list = unavailable_resource_key_dict[verb]
            #随机挑选一个不可访问资源key
            res_key = random.choice(unavailable_resource_key_list)
            un_res = all_resource[res_key]
            ne_data = {
                    'service_account': sa,
                    'resource': un_res,
                    'verb': verb
                }
            negative_data_list.append(ne_data)
        
        #添加到negative_data_dict
        if negative_data_list:
            negative_data_dict[sa_key] = negative_data_list
    
    #写入文件
    for sa_key, data_list in positive_data_dict.items():
        new_sa_key = sa_key.replace('/','.')
        path = f'train-dataset/positive/{new_sa_key}.json'
        with open(path, 'w', encoding='utf-8') as file:
            for data in data_list:
                file.write(json.dumps(data))
                file.write('\n')
    
    for sa_key, data_list in negative_data_dict.items():
        new_sa_key = sa_key.replace('/','.')
        path = f'train-dataset/negative/{new_sa_key}.json'
        with open(path, 'w', encoding='utf-8') as file:
            for data in data_list:
                file.write(json.dumps(data))
                file.write('\n')
    

#生成测试样本：
def generate_test_data():
    kubernetes_client = KubernetesClient(config_file="config")
    service_account_dict = kubernetes_client.get_all_serviceaccounts()
    service_account_with_rule_dict = kubernetes_client.get_all_service_account_with_rules()
    all_resource_dict = kubernetes_client.get_all_resource()
    all_resource = {}
    #加工成一级索引的resource
    for ns, kind_key_dict in all_resource_dict.items():
        for kind_key, resource_list in kind_key_dict.items():
            for resource in resource_list:
                resource_key = f"{kind_key}/{resource['metadata']['name']}"
                all_resource[resource_key] = resource
    
    test_data_dict = {}
    for sa_key, sa_with_rule in service_account_with_rule_dict.items():
        service_account = service_account_dict[sa_key]
        event_feature_list = []
        auth_dict = get_available_resource_of_service_account(sa_with_rule)
        for verb, resource_key_list in auth_dict.items():
            for resource_key in resource_key_list:
                #如果是子资源，先暂时按照父资源处理
                if resource_key.startswith('[sub]'):
                    resource_key = resource_key.split()[1]
                #print(resource_key)
                if resource_key not in all_resource:
                    print(f"all_resource 中没有 {resource_key}")
                    continue
                resource = all_resource[resource_key]
                clear_data(resource)
                clear_data(service_account)
                event_feature = {
                    'service_account': service_account,
                    'resource': resource,
                    'verb': verb
                }
                event_feature_list.append(event_feature)
        test_data_dict[sa_key] = event_feature_list
    new_test_data_dict = {key: value for key, value in test_data_dict.items() if value}
    
    
    for sa_key, event_feature_list in new_test_data_dict.items():
        new_sa_key = sa_key.replace('/','.')
        path = f'./test-dataset/{new_sa_key}.json'
        if os.path.exists(path):
            # 如果存在，删除文件
            os.remove(path)
        with open(path, 'w', encoding='utf-8') as file:
            for event_feature in event_feature_list:
                file.write(json.dumps(event_feature))
                file.write('\n')
                

def get_available_resource_of_service_account(service_account_with_rules):
    service_account_name = service_account_with_rules['metadata']['name']
    service_account_ns = service_account_with_rules['metadata']['namespace']
    rule_list = service_account_with_rules['rule_list']
    cluster_rule_list = service_account_with_rules['cluster_rule_list']
    
    #获取当前的group_versions
    kubernetes_client = KubernetesClient(config_file="config")
    group_version_dict = kubernetes_client.get_api_versions_groups_and_kinds()
    all_resource = kubernetes_client.get_all_resource()  
    all_namespace = kubernetes_client.get_all_namespaces()
    auth_dict = {
        'get':[],
        'list':[],
        'create':[],
        'delete':[],
        'watch':[],
        'update':[],
        'patch':[]
    }
    for rule in rule_list:
        auth_dict_of_one_rule = analyze_rule(rule, service_account_ns, group_version_dict, all_resource[service_account_ns])
        for key, value in auth_dict_of_one_rule.items():
            if key in auth_dict:
                auth_dict[key].extend(value)
    for cluster_rule in cluster_rule_list:
        auth_dict_of_one_cluster_rule = analyze_cluster_rule(cluster_rule, group_version_dict, all_namespace, all_resource)
        for key, value in auth_dict_of_one_cluster_rule.items():
            if key in auth_dict:
                auth_dict[key].extend(value)
    return auth_dict
    

def analyze_cluster_rule(rule, group_version_dict, all_namespace_list, all_resource_dict):
    if 'apiGroups' not in rule: #说明是非资源规则
        print(json.dumps(rule, indent=2))
        return {}
    rule_api_group_list = rule['apiGroups']
    rule_resource_list = rule['resources']
    rule_verb_list = rule['verbs']
    rule_name_list = rule['resourceNames'] if 'resourceNames' in rule else ['*']
    
    new_rule_api_group_set = set()
    
    group_version_list = group_version_dict.keys()
    for rule_api_group in rule_api_group_list:
        for group_version in group_version_list:
            group = ''
            if "/" in group_version:
                group = group_version.split('/')[0]
            if fnmatch.fnmatch(group, rule_api_group):
                new_rule_api_group_set.add(group_version)
    
    resource_key_set = set()
    for rule_resource in rule_resource_list:
        for group_version in new_rule_api_group_set:
            kind_list = group_version_dict[group_version]
            for kind in kind_list:
                if kind['namespaced']:
                    kind_name = kind['name']
                    if '/' in kind_name: #说明是子资源
                        splited_kind = kind_name.split('/', 1)
                        if fnmatch.fnmatch(splited_kind[0], rule_resource) or fnmatch.fnmatch(kind_name, rule_resource):
                            for namespace in all_namespace_list:
                                resource_key_set.add(f"[sub] {group_version}/{namespace}/{splited_kind[0]} {splited_kind[1]}")
                    else:
                        if fnmatch.fnmatch(kind['name'], rule_resource):
                            for namespace in all_namespace_list:
                                resource_key_set.add(f"{group_version}/{namespace}/{kind['name']}")
                else:
                    kind_name = kind['name']
                    if '/' in kind_name: #说明是子资源
                        splited_kind = kind_name.split('/', 1)
                        if fnmatch.fnmatch(kind['name'].split('/')[0], rule_resource) or fnmatch.fnmatch(kind_name, rule_resource):
                            resource_key_set.add(f"[sub] {group_version}/cluster-level/{splited_kind[0]} {splited_kind[1]}")
                    else:
                        if fnmatch.fnmatch(kind['name'], rule_resource):
                            resource_key_set.add(f"{group_version}/cluster-level/{kind['name']}")
    
    # for resource_key in resource_key_set:
    #     print(resource_key)
    
    resource_name_key_list = []
    
    for resource_key in resource_key_set:
        for namespace, namespaced_resource_dict in all_resource_dict.items():
            if resource_key.startswith('[sub]'): #如果是子资源，则匹配其父资源
                splited_resource_key = resource_key.split()
                parent_resource_key = splited_resource_key[1]
                if parent_resource_key not in namespaced_resource_dict:
                    #print(f'暂无[{resource_key}]的父资源')
                    continue
                temp_resource_list = namespaced_resource_dict[parent_resource_key]
                for resource in temp_resource_list:
                    name = resource['metadata']['name']
                    for rule_name in rule_name_list:
                        if fnmatch.fnmatch(name, rule_name):
                            resource_name_key_list.append(f"[sub] {parent_resource_key}/{name} {splited_resource_key[2]}")
                            break
            else:
                if resource_key not in namespaced_resource_dict:
                    #print(f'暂无[{resource_key}]类型资源')
                    continue
                temp_resource_list = namespaced_resource_dict[resource_key]
                for resource in temp_resource_list:
                    name = resource['metadata']['name']
                    for rule_name in rule_name_list:
                        if fnmatch.fnmatch(name, rule_name):
                            resource_name_key_list.append(f"{resource_key}/{name}")
                            break
    # print("=========================================")
    # for resource_name in resource_name_key_list:
    #     print(resource_name)
    
    
    new_rule_verb_list = ['get','list','create','delete','update','patch','watch'] if "*" in rule_verb_list else rule_verb_list
    # print(new_rule_verb_list)

    auth_dict = {}
    for verb in new_rule_verb_list:
        auth_dict[verb] = list(resource_name_key_list)
    return auth_dict

def analyze_rule(rule, namespace, group_version_dict, namespaced_resource_dict):
    if 'apiGroups' not in rule: #说明是非资源规则
        print(json.dumps(rule, indent=2))
        return {}
    rule_api_group_list = rule['apiGroups']
    rule_resource_list = rule['resources']
    rule_verb_list = rule['verbs']
    rule_name_list = rule['resourceNames'] if 'resourceNames' in rule else ['*']
    
    new_rule_api_group_set = set()
    
    group_version_list = group_version_dict.keys()
    for rule_api_group in rule_api_group_list:
        for group_version in group_version_list:
            group = ''
            if "/" in group_version:
                group = group_version.split('/')[0]
            if fnmatch.fnmatch(group, rule_api_group):
                new_rule_api_group_set.add(group_version)
    
    resource_key_set = set()
    for rule_resource in rule_resource_list:
        for group_version in new_rule_api_group_set:
            kind_list = group_version_dict[group_version]
            for kind in kind_list:
                if kind['namespaced']:
                    kind_name = kind['name']
                    if '/' in kind_name: #说明是子资源
                        splited_kind = kind_name.split('/', 1)
                        #规则中也有可能是子资源
                        if fnmatch.fnmatch(splited_kind[0], rule_resource) or fnmatch.fnmatch(kind_name, rule_resource):
                            resource_key_set.add(f"[sub] {group_version}/{namespace}/{splited_kind[0]} {splited_kind[1]}")
                    else:
                        if fnmatch.fnmatch(kind['name'], rule_resource):
                            resource_key_set.add(f"{group_version}/{namespace}/{kind['name']}")
    
    resource_name_key_list = []
    
    for resource_key in resource_key_set:
        
        if resource_key.startswith('[sub]'): #如果是子资源，则匹配其父资源
            splited_resource_key = resource_key.split()
            parent_resource_key = splited_resource_key[1]
            if parent_resource_key not in namespaced_resource_dict:
                #print(f'暂无[{resource_key}]的父资源')
                continue
            temp_resource_list = namespaced_resource_dict[parent_resource_key]
            for resource in temp_resource_list:
                name = resource['metadata']['name']
                for rule_name in rule_name_list:
                    if fnmatch.fnmatch(name, rule_name):
                        resource_name_key_list.append(f"[sub] {parent_resource_key}/{name} {splited_resource_key[2]}")
                        break
        else:
            if resource_key not in namespaced_resource_dict:
                #print(f'暂无[{resource_key}]类型资源')
                continue
            temp_resource_list = namespaced_resource_dict[resource_key]
            for resource in temp_resource_list:
                name = resource['metadata']['name']
                for rule_name in rule_name_list:
                    if fnmatch.fnmatch(name, rule_name):
                        resource_name_key_list.append(f"{resource_key}/{name}")
                        break
        
    
    # for resource_name_key in resource_name_key_list:
    #     print(resource_name_key)
    
    
    new_rule_verb_list = ['get','list','create','delete','update','patch','watch'] if "*" in rule_verb_list else rule_verb_list
    # print(new_rule_verb_list)
    auth_dict = {}
    for verb in new_rule_verb_list:
        auth_dict[verb] = list(resource_name_key_list)
    return auth_dict

def filter_auth_dict(auth_dict): #如果父资源存在，则没必要记录子资源
    filterd_auth_dict = {}
    for verb, resource_key_list in auth_dict.items():
        filterd_resource_key_list = []
        for resource_key in resource_key_list:
            if resource_key.startswith("[sub]") and resource_key.split()[1] in resource_key_list:
                continue
            filterd_resource_key_list.append(resource_key)
        filterd_auth_dict[verb] = filterd_resource_key_list
    return filterd_auth_dict

#清洗掉不需要的字段
def clear_data(data_dict):
    metadata = data_dict["metadata"]
    if "managedFields" in metadata:
        del metadata["managedFields"]
    if "annotations" in metadata:
        if "kubectl.kubernetes.io/last-applied-configuration" in metadata["annotations"]:
            del metadata["annotations"]["kubectl.kubernetes.io/last-applied-configuration"]
            



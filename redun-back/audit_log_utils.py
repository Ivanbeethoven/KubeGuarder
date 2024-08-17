import json
import os
from kubernetes_client import KubernetesClient
from kubernetes import client, config
from urllib.parse import urlparse, urlunparse, parse_qs

def read_json_lines(file_path):
    result = []
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            try:
                json_dict = json.loads(line)
                result.append(json_dict)
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON in line: {line.strip()}. Error: {e}")
    return result

#处理审计日志文件夹，获取正样本
def process_log_folder(log_folder_path):
    kubernetesClient = KubernetesClient("config")
    all_serviceaccounts = kubernetesClient.get_all_serviceaccounts()
    all_resources = kubernetesClient.get_all_resource()
    
    all_event_feature_dict = {}
    service_account_dict = kubernetesClient.get_all_serviceaccounts()
    for key in service_account_dict.keys():
        all_event_feature_dict[key] = []
    
    for filename in os.listdir(log_folder_path):
        file_path = os.path.join(log_folder_path, filename)
        event_feature_list = []
        if os.path.isfile(file_path) and filename.endswith('.log'):
            event_list = read_json_lines(file_path)
            for event in event_list:
                one_event_features = process_event(event_dict=event, all_service_account_dict=all_serviceaccounts, all_resource_dict=all_resources)
                if one_event_features is not None:
                    event_feature_list.extend(one_event_features)
        
        for event_feature in event_feature_list:
            #过滤非资源请求
            if 'spec' in event_feature['resource'] and 'nonResourceAttributes' in event_feature['resource']['spec']:
                continue
            clear_data(event_feature["service_account"])
            clear_data(event_feature["resource"])
            key = f"{event_feature['service_account']['metadata']['namespace']}/{event_feature['service_account']['metadata']['name']}"
            all_event_feature_dict[key].append(event_feature)
        #过滤掉空数组
        new_all_event_feature_dict = {key: value for key, value in all_event_feature_dict.items() if value}
        
    return new_all_event_feature_dict

#根据event找出对应的服务账户和操作的资源
def process_event(event_dict, all_service_account_dict, all_resource_dict):
    if not event_dict['stage'] == "ResponseComplete":
        return None
    if event_dict['responseStatus']['code'] >= 300:
        return None
    event_feature_list = []
    #提取账户特征
    username = event_dict['user']['username']
    if not username.startswith("system:serviceaccount:"):
        return None
    
    splitList = username.split(':')
    serviceaccount_name = splitList[-1]
    serviceaccount_namespace = splitList[-2]
    serviceaccount_key = f"{serviceaccount_namespace}/{serviceaccount_name}"
    if not serviceaccount_key in all_service_account_dict:
        return None
    if "objectRef" not in event_dict:
        return None
    serviceaccount = all_service_account_dict[serviceaccount_key]

    #提取操作特征
    verb = event_dict["verb"]

    #提取资源特征
    if verb == "get" or verb == "delete" or verb == "update" or verb == "patch":
        object_ref = event_dict["objectRef"]
        resource_kind = object_ref["resource"]
        api_version = object_ref['apiVersion']
        if "apiGroup" in object_ref:
            api_version = f"{object_ref['apiGroup']}/{object_ref['apiVersion']}"
        resource_name = object_ref["name"]
        resource_namespace = "cluster-level"
        if "namespace" in object_ref:
            resource_namespace = object_ref["namespace"]
        resource_key = f"{api_version}/{resource_namespace}/{resource_kind}/{resource_name}"
        if not resource_key in all_resource_dict:
            #print(f"[{verb}] {resource_key} NO")
            #print(json.dumps(event_dict,indent=2))
            return None
        # else:
        #     print(f"[{verb}] {resource_key} YES")
        resource = all_resource_dict[resource_key]
        event_feature_list.append(
            {
                "service_account":serviceaccount,
                "resource": resource,
                "verb": verb
            }
        )
    elif verb == 'watch':
        object_ref = event_dict["objectRef"]
        kind = object_ref["resource"]
        api_version = object_ref["apiVersion"]
        if "apiGroup" in object_ref:
            api_version = f"{object_ref['apiGroup']}/{object_ref['apiVersion']}"

        #如果指定了名字，说是针对单个资源的watch，
        if "name" in object_ref:
            resource_name = object_ref["name"]
            resource_namespace = "cluster-level"
            if "namespace" in object_ref:
                resource_namespace = object_ref["namespace"]
            resource_key = f"{api_version}/{resource_namespace}/{kind}/{resource_name}"
            if not resource_key in all_resource_dict:
                #print(f"[{verb}] {resource_key} NO")
                #print(json.dumps(event_dict,indent=2))
                return None
            # else:
            #     print(f"[{verb}] {resource_key} YES")
            resource = all_resource_dict[resource_key]
            event_feature_list.append(
                {
                    "service_account":serviceaccount,
                    "resource": resource,
                    "verb": verb
                }
            )
        #如果没有指定名字，说明是对一个资源集合的watch
        else:
            config.load_kube_config(config_file="config")
            api_client = client.ApiClient()
            request_path = event_dict["requestURI"]
            request_path = filter_param(request_path)
            response = api_client.call_api(request_path, 'GET', response_type='object')[0]
            responseObject_dict = api_client.sanitize_for_serialization(response)
            
            api_version = responseObject_dict["apiVersion"]
            kind_kind = responseObject_dict["kind"][:-4]
            
            items = responseObject_dict["items"]
            if items is None:
                return None
            for resource_item in items:
                #填充列表项缺失字段
                resource_item['apiVersion'] = api_version
                resource_item['kind'] = kind_kind
                event_feature_list.append(
                    {
                        "service_account":serviceaccount,
                        "resource": resource_item,
                        "verb": verb
                    }
                )
            
    elif verb == "list":
        object_ref = event_dict["objectRef"]
        config.load_kube_config(config_file="config")
        api_client = client.ApiClient()
        request_path = event_dict["requestURI"]
        request_path = filter_param(request_path)
        response = api_client.call_api(request_path, 'GET', response_type='object')[0]
        responseObject_dict = api_client.sanitize_for_serialization(response)
        kind = object_ref["resource"]
        api_version = responseObject_dict["apiVersion"]
        kind_kind = responseObject_dict["kind"]
        
        items = responseObject_dict["items"]
        if items is None:
            return None
        for resource_item in items:
            #填充列表项缺失字段
            resource_item['apiVersion'] = api_version
            resource_item['kind'] = kind_kind
            event_feature_list.append(
                {
                    "service_account":serviceaccount,
                    "resource": resource_item,
                    "verb": verb
                }
            )
        
    elif verb == "create":
        # 对于create请求，从requestObject中提取特征，手动创建特征
        resource = event_dict["requestObject"]
        event_feature_list.append(
                {
                    "service_account":serviceaccount,
                    "resource": resource,
                    "verb": verb
                }
            )
    
    return event_feature_list

#清洗掉不需要的字段
def clear_data(data_dict):
    metadata = data_dict["metadata"]
    if "managedFields" in metadata:
        del metadata["managedFields"]
    if "annotations" in metadata:
        if "kubectl.kubernetes.io/last-applied-configuration" in metadata["annotations"]:
            del metadata["annotations"]["kubectl.kubernetes.io/last-applied-configuration"]
            

#展平字典
def flatten_dict(input_dict, prefix=''):
    flat_dict = {}
    for key, value in input_dict.items():
        new_key = f'{prefix}.{key}' if prefix else key
        if isinstance(value, dict):
            flat_dict.update(flatten_dict(value, new_key))
        else:
            flat_dict[new_key] = value
    return flat_dict

def filter_param(url_str):
    # 解析 URL
    parsed_url = urlparse(url_str)
    # 解析查询参数
    query_params = parse_qs(parsed_url.query)

    # 删除名为 "resourceVersion" 的查询参数
    if "resourceVersion" in query_params:
        del query_params["resourceVersion"]
    if "allowWatchBookmarks" in query_params:
        del query_params["allowWatchBookmarks"]
    if "timeoutSeconds" in query_params:
        del query_params["timeoutSeconds"]
    if "watch" in query_params:
        del query_params["watch"]

    # 将更新后的查询参数重新构建为字符串
    updated_query = "&".join(f"{key}={value}" for key, values in query_params.items() for value in values)

    # 更新 URL 对象的查询部分
    updated_url = parsed_url._replace(query=updated_query)

    # 重新构建 URL 字符串
    final_url = urlunparse(updated_url)

    return final_url


            








# 替换 'your_file.txt' 为你的文件路径
# event_featrue_dict = process_log_folder("./logs")
# for sa_key, event_feature_list in event_featrue_dict.items():
#     new_sa_key = sa_key.replace('/','.')
#     path = f'./train-dataset/positive/{new_sa_key}.json'
#     # if os.path.exists(path):
#     #     # 如果存在，删除文件
#     #     os.remove(path)
#     with open(path, 'w', encoding='utf-8') as file:
#         for event_feature in event_feature_list:
#             file.write(json.dumps(event_feature))
#             file.write('\n')



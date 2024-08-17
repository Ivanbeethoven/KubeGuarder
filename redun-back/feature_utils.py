import json
import os
import pandas as pd
from kubernetes import client, config



def get_labeled(positive_path, negative_path):
    pos_feature_list = feature_extract(positive_path)
    neg_feature_list = feature_extract(negative_path)
    data = []
    for text in pos_feature_list:
        data.append([text, 1])
    for text in neg_feature_list:
        data.append([text, 0])
    #测试
    for item in data:
        print(item)
    df = pd.DataFrame(data, columns=['text', 'label'])
    df.to_csv('./train-dataset/labeled_train_data.csv', index=False, encoding='utf-8')

def get_test(test_path):
    test_feature_list = feature_extract(test_path)
    data = []
    for text in test_feature_list:
        data.append([text, 0])
    #测试
    for item in data:
        print(item)
    df = pd.DataFrame(data, columns=['text', 'label'])
    df.to_csv('./test-dataset/test_data.csv', index=False, encoding='utf-8')


def feature_extract(data_base_file):
    all_dict_list = process_folder(data_base_file)
    all_feature_list = []

    for dict in all_dict_list:
        sa = dict['service_account']
        resource = dict['resource']
        verb = dict['verb']
        #抽取文本特征
        sa_fea = get_text_feature_of_service_account(sa)
        res_fea = get_text_feature_of_resource(resource)
        account_info = " ".join([f"{k}: {v}" for k, v in sa_fea.items()])
        resource_info = " ".join([f"{k}: {v}" for k, v in res_fea.items()])
        text = f"Account info: [{account_info}] Resource info: [{resource_info}] Action: {verb}"
        if len(text) > 512:
            print(len(text))
        all_feature_list.append(text)
    
    return all_feature_list
        
# 处理数据库文件夹，读取所有数据
def process_folder(folder_path):
    all_dict_list = []
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path) and filename.endswith('.json'):
            dict_list = process_json_file(file_path)
            all_dict_list.extend(dict_list)
    return all_dict_list
# 处理数据库文件
def process_json_file(file_path):
    dict_list = []
    with open(file_path, 'r') as file:
        for line in file:
            try:
                json_dict = json.loads(line)
                dict_list.append(json_dict)
            except json.JSONDecodeError as e:
                continue
    return dict_list

def get_text_feature_of_resource(resource):
    resource_feature_dict = {}
    metadata = resource['metadata']
    if 'namespace' not in metadata:
        is_cluster_level = True
        ns = 'cluster-level'
    else:
        is_cluster_level = False
        ns = metadata['namespace']
    group_version = resource['apiVersion']
    if group_version == "v1":
        group = "core"
        version = "v1"
    else:
        temp_list2 = group_version.split('/')
        group = temp_list2[0]
        version = temp_list2[1]
    kind = resource['kind']
    
    filtered_labels = {}
    filtered_annotations = {}
    if 'labels' in resource["metadata"]:
        labels = resource["metadata"]["labels"]
        filtered_labels = {key: value for key, value in labels.items() if len(json.dumps(value)) <= 30}
    if 'annotations' in resource["metadata"]:
        annotations = resource["metadata"]["annotations"]
        filtered_annotations = {key: value for key, value in annotations.items() if len(json.dumps(value)) <= 30}
        
    #资源名称
    name = "-"
    if "name" in resource["metadata"]:
        name = resource["metadata"]["name"]
    
    #构建特征字典
    resource_feature_dict = {
        'kind': kind,
        'namespace': ns,
        'clustered': is_cluster_level,
        'name': name,
        'group': group,
        'version':version,
        'labels': filtered_labels,
        'annotations': filtered_annotations,
        #'create_time': create_time
    }
    return resource_feature_dict
    

def get_text_feature_of_service_account(service_account):
    service_account_feature_dict = {}
    filtered_labels = {}
    filtered_annotations = {}
    if 'labels' in service_account["metadata"]:
        labels = service_account["metadata"]["labels"]
        filtered_labels = {key: value for key, value in labels.items() if len(json.dumps(value)) <= 30}
        
    if 'annotations' in service_account["metadata"]:
        annotations = service_account["metadata"]["annotations"]
        filtered_annotations = {key: value for key, value in annotations.items() if len(json.dumps(value)) <= 30}
    service_account_feature_dict = {
        'namespace': service_account['metadata']['namespace'],
        'name': service_account['metadata']['name'],
        'labels': filtered_labels,
        'annotations': filtered_annotations
    }
    return service_account_feature_dict

#get_labeled("./train-dataset/positive", "./train-dataset/negative")
#get_test("./test-dataset")
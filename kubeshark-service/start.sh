#!/bin/bash

# 等待 Kubernetes 成功启动
while ! kubectl get nodes | grep -q 'Ready'; do
    echo "等待 Kubernetes 启动..."
    sleep 10
done

# 运行 kubeshark tap 命令
/root/code/kubeshark/bin/kubeshark__ tap

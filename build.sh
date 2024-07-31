#!/bin/bash

# 定义要编译的子目录列表
projects=("kube-guard" "webhook-admission-controller")

# 创建一个存放所有JAR文件的目录
output_dir="jar"
mkdir -p $output_dir

# 遍历每个子目录并执行mvn clean package命令
for project in "${projects[@]}"; do
  echo "Building project in directory: $project"
  cd $project
  mvn clean package
  if [ $? -ne 0 ]; then
    echo "Build failed for project: $project"
    exit 1
  fi
  # 复制生成的JAR文件到output_dir目录中
  jar_file=$(ls target/*.jar)
  cp $jar_file ../$output_dir/
  cd ..
done

echo "All projects built successfully. JAR files are copied to $output_dir."

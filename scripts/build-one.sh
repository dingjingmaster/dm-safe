#!/bin/bash

set -e

# 项目根目录。realpath 能把脚本的相对路径解析成绝对路径。
curDir=$(dirname $(dirname $(realpath -- "$0")))
srcDir=$curDir/src

# 当前机器架构，用于拼接最终 ko 文件名。
osArch=$(uname -m)

# 本机已安装内核模块目录，每个子目录通常对应一个内核版本。
modulesDir='/lib/modules'

# 读取发行版名称并压缩成适合做目录名的一段字符串。
osInfo=$(cat /etc/os-release | grep PRETTY_NAME | awk '{print substr($$0,13)}')
osName=$(cat /etc/os-release | grep -e ^NAME= | sed 's/\"//g' | awk -F'=' '{print $2}' | tr '[:lower:]' '[:upper:]')
osInfo="${osInfo//LTS/}"
osInfo="${osInfo// /}"
osInfo="${osInfo//\"/}"

# ko 输出目录形如 ko/<发行版>/safe_fs-<发行版>-<架构>-<内核版本>.ko。
koDir="$curDir/ko"
kernelDir="$koDir/$osInfo"
osVersion=$(uname -r)

if [[ "$#" -eq 1 ]];then
    echo "Will build '$1'"
fi

# 特定发行版的目录名需要归一化，避免 PRETTY_NAME 里带空格或小版本导致输出路径不稳定。
if [[ "$osInfo" =~ "CentOS" ]];then
    versionID=$(cat /etc/os-release | grep VERSION_ID | awk -F'=' '{print $2}' | sed s/\"//g)
    if [ "$versionID" -eq 10 ]; then
        osInfo=CENTOS10
        osName=CENTOS10
    else
        osInfo=CENTOS7
        osName=CENTOS7
    fi
    kernelDir="$koDir/$osInfo"
    echo "version ID: ${versionID}"
elif [[ "$osInfo" =~ "UOS" ]]; then
    if [[ -f /etc/product-info ]]; then
        minorVersion=$(cat /etc/product-info | grep MinorVersion | awk -F'=' '{print $2}')
        osInfo="UOS-${minorVersion}"
        osName="UOS"
    else
        echo 'Not supported UOS version!'
        exit 1
    fi
    kernelDir="$koDir/$osInfo"
    echo "version ID: ${minorVersion}"
fi


[[ ! -d "$kernelDir" ]] && mkdir -p "$kernelDir"

# 在 /lib/modules 下查找和用户参数匹配的内核版本。例如：
#   ./scripts/build-one.sh 5.4.18-35
# 会匹配 /lib/modules/5.4.18-35-generic。
for m in $(ls "$modulesDir" | sort);
do
    koFullName=$kernelDir/safe_fs-${osInfo}-${osArch}-${m}.ko
    if [[ "$m" =~ "$1" ]]; then
        echo "Start build ..."
        buildPath=$modulesDir/$m/build
        echo "KO full name: $koFullName"

        # 先删掉旧 ko，再调用项目 Makefile 走目标内核头目录编译。
        rm -f "$koFullName"
        make isRelease=1 osHeader=$buildPath osVersion=$m osInfo=$osInfo osName=$osName clean
        make isRelease=0 osHeader=$buildPath osVersion=$m osInfo=$osInfo osName=$osName debug

        # 编译完成后按项目约定签名并拷贝/输出到 koFullName。
        ${curDir}/scripts/sign-file.sh "${buildPath}" "${koFullName}"
        break
    fi
done

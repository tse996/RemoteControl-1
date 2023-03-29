# 远程主机控制工具
## 0. 运行
server里main.py是服务端
根目录main.py是控守端
## 1. 介绍
本项目为哈尔滨工业大学（威海）网络空间安全专业大三上学期网络空间安全课程设计I选题之一。 

主要功能如下：

1. 监控目标主机桌面
2. 远程键鼠控制
3. 监控目标主机网络活动
4. 监控目标主机硬件资源使用情况
5. 中断/恢复目标主机网络访问
6. 对数据传输进行简单的加密

## 2. 开发环境
本机：Windows 10, Pycharm 2020.3, Python 3.9.1

目标主机：Windows 10, Python 3.9.0

## 3. 使用方法

完整的报告请参考我的[这篇博客](https://www.litcu.cn/archives/12)。

目标主机（最好为windows，linux下功能不完全）：

将server目录复制到目的主机，使用Python运行main.py

本机:

```bash
pip install -r requirements.txt
python main.py
```

## 4. 目录介绍
1. venv: 虚拟环境（Python 3.9.1）
2. source: 包含界面源文件、图片以及RSA加密公钥
3. server: 包含目标主机端程序，与RSA私钥

## 5. 目前BUG
1. 键盘控制只能使用二十六个英文字母，其他按键可能导致程序崩溃
2. 待补充

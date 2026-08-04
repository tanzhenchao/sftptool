# SFTP 运维工具使用说明

# 1. 工具概述
本工具专为 SFTP 服务运维管理开发，可一站式实现 SFTP 服务全生命周期管理，核心功能涵盖：SFTP 用户账号管理、AD 域账号对接、用户家目录配置、身份密钥管理、存储配额管控、操作审计日志、数据备份等运维常用场景，适配 Oracle Linux 9.x 系统环境。
# 2. SFTP 服务部署方案
本工具支持两种安全认证部署模式，可根据业务需求选择，详细配置方案参考官方技术文档：
## 2.1. AD 域集成认证部署
如需实现 SFTP 服务对接 AD 域账号认证，参考文档《如何基于 Oracle Linux 9.x 配置 SFTP 集成 AD 域》：https://www.cmdschool.org/archives/24140
## 2.2. 邮箱 OTP 二次认证部署
如需开启 SFTP 邮箱验证码 2FA 双重安全认证，提升服务访问安全性，参考文档《如何基于 Oracle Linux 9.x 实现 SFTP 邮箱 2FA 认证》：https://www.cmdschool.org/archives/24107
# 3. 工具部署与使用方法
## 3.1 环境依赖安装
执行以下命令安装工具运行所需全部依赖组件：
~~~
# dnf install -y putty bc mkpasswd-expect expect bzip2 postfix mailx openldap-clients autofs quota
~~~
## 3.2 工具安装部署
重要说明：工具源码下载地址为境外链接，当前无法正常访问，可等待链接恢复后执行以下完整部署命令，完成工具安装、权限配置、配置文件部署：
~~~
# wget https://codeload.github.com/tanzhenchao/sftptool/zip/refs/heads/for-ad-user -O sftptool-for-ad-user.zip
# unzip sftptool-for-ad-user.zip
# mv sftptool-for-ad-user/sftptool.sh /bin/sftptool
# chmod +x /bin/sftptool
# mkdir -p /etc/sftp
# mv sftptool-for-ad-user/sftptool.conf /etc/sftp/sftptool.conf
~~~
## 3.3 工具运行与命令说明
安装完成后，直接执行以下命令启动工具：
~~~
sftptool
~~~
工具支持八大核心运维指令，具体使用格式如下：
~~~
Usage: /usr/bin/sftptool {user|home|ca|passwd|quota|share|log|ldap|backup}
~~~
指令释义：用户管理、家目录管理、证书管理、密码管理、配额管理、共享管理、日志审计、LDAP 对接、数据备份

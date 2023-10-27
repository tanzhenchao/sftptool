# 工具的简介
一个管理SFTP服务的工具，用于管理SFTP用户系统账号、用户目录、身份秘钥、配额、审核日志、备份等工具

# SFTP服务的部署方法
请参阅本人博客文档《如何部署sftptool的sftp服务运行环境？》，https://www.cmdschool.org/archives/22045

# 工具的使用方法
dnf install -y putty bc expect bzip2 postfix mailx openldap-clients autofs  
wget https://raw.githubusercontent.com/tanzhenchao/sftptool/main/sftptool.sh  
mv sftptool.sh /usr/bin/sftptool  
chmod +x /bin/sftptool  
sftptool  
Usage: /usr/bin/sftptool {user|home|ca|quota|ldap|backup}

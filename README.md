# 工具的简介
一个管理SFTP服务的工具，用于管理SFTP用户系统账号、用户目录、身份秘钥、配额、审核日志、备份等工具

# SFTP服务的部署方法
请参阅本人博客文档部署SFTP，https://www.cmdschool.org/archives/15658

# 工具的使用方法
wget https://raw.githubusercontent.com/tanzhenchao/sftptool/main/sftptool.sh  
mv sftptool.sh /usr/bin/sftptool  
sftptool  
Usage: /usr/bin/sftptool {user|home|ca|quota|ldap|backup}  

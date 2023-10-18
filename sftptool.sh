#!/bin/bash

source /etc/profile

authorizedKeysRootDir="/etc/ssh/sftpd_authorized_keys"
authorizedKeysName="authorized_keys"
sftpDataDir="/data/sftp"
mailBox="/var/mail"
mailFrom="sftpService@cmdschool.org"
logAudit="/var/log/audit/audit.log"
logAlert="/var/log/sftp/alert.log"
logChange="/var/log/sftp/change.log"
logMessage="/var/log/sftp/message.log"
logDisable=true
backupDir="/backup/sftp"
quotaPath="/dev/mapper/ds-data"
sftpGroupName="sftponly"
sftpHomeName="myhome"
sftpUserInfoFileName="userInfo"
defaultQuota="8GB"
ldapHost="ldapServer.cmdschool.org"
ldapPort="389"
ldapBindDN="uid=directory manager,ou=People,dc=cmdschool,dc=org"
ldapPasswd="cn=directory manager password"
ldapBaseDN="ou=people,dc=cmdschool,dc=org"
defaultExpires="180"
alertDays="30"
alertFrequency="10"
autoMastConf="/etc/auto.master"
autoSftpConf="/etc/auto.sftp"

parameter1="$3"
parameter2="$4"
parameter3="$5"
parameter4="$6"

cd ~
if [ ! -d `dirname "$logAlert"` ]; then
	mkdir -p `dirname "$logAlert"`
fi
if [ ! -d `dirname "$logChange"` ]; then
	mkdir -p `dirname "$logChange"`
fi
if [ ! -d `dirname "$logMessage"` ]; then
	mkdir -p `dirname "$logMessage"`
fi

nowTime=`date '+%Y-%m-%d %H:%M:%S'`

checkJrRule() {
	jrNumber="`echo "$1" | tr 'a-z' 'A-Z'`"
	if [[ "$jrNumber" =~ ^(DG|CA|HK)[0-9]{4}[0-9]{2}[0-9]{2}(JR)[0-9]{4}$ ]]; then
		return 0
	else
		return 1
	fi
}

checkMailRule() {	
	if [[ "$1" == ?*@?*.?* ]]; then
		return 0
	else
		return 1
	fi
}

addUser() {
	# Function implementation to add sftp new user.
	sftpAccountName="$parameter1"
	jrNumber="$parameter2"
	endUserStaffNumber="$parameter3"
	sftpPasswd="$parameter4"

	if [ "$endUserStaffNumber" == "" ] || [ "$jrNumber" == "" ] || [ "$sftpAccountName" == "" ]; then
		echo "Usage: $0 user add <sftp account> <JR No.> <endUser staff No.> [sftp passwd]"
		exit 1;
	fi

	endUserStaffNumber="`echo "$endUserStaffNumber" | tr 'a-z' 'A-Z'`"

        sftpUserKeysRootDir="$authorizedKeysRootDir"'/'"$sftpAccountName"
	sftpUserInfo="$sftpUserKeysRootDir"'/'"$sftpUserInfoFileName"

	userMail=`$0 ldap get "$endUserStaffNumber" "mail" | sed 's/mail: //g'`
	abnormal="0"	
	if ! checkMailRule "$userMail"; then
		echo 'The format of the automatically obtained mail '"$userMail"' address is abnormal!'
		abnormal="1"
	fi
	if [ "$abnormal" == "1" ]; then
		read -p 'Please enter the mail address of user "'"$endUserStaffNumber"'" :' userMail
	fi
	if ! checkMailRule "$userMail"; then
		echo 'Email address "'$userMail'" does not meet the rules!'
		exit 1
	fi

	jrNumber="`echo "$jrNumber" | tr 'a-z' 'A-Z'`"
	if ! checkJrRule "$jrNumber"; then
		echo 'JR number "'$jrNumber'" does not meet the rules!'
		exit 1
	fi

	echo '#------------------------------------------------'
	echo 'End User Staff: '"$endUserStaffNumber"
	echo 'End User Mail: '"$userMail"
	echo 'JR: '"$jrNumber"
	echo 'SFTP Account: '"$sftpAccountName"
	for ((;;)); do
		read -p 'Confirm user information, Continue (y/n)?' choice
		case "$choice" in 
			y|Y )
				echo "yes"
				break
		        	;;
			n|N )
				echo "no"
				exit 0
				;;
			* )
				echo "invalid!"
				;;
		esac
	done

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 0 ]; then
		echo 'User "'"$sftpAccountName"'" already exists!'
		exit 1;
	fi

	useradd "$sftpAccountName" -g "$sftpGroupName" -M -d '/'"$sftpHomeName" -s /bin/false
	$0 home add "$sftpAccountName" "$jrNumber"
	for ((;;)); do
		echo ''
		echo '#------------------------------------------------'
		read -p "Please enter the space quota size requested by the user(default $defaultQuota):" quota
		$0 quota set "$sftpAccountName" "$jrNumber" "$quota"
		if [ $? = 0 ]; then
			break
		fi
	done
	$0 ca add "$sftpAccountName" "$jrNumber"

	expires=`date -d "+$defaultExpires day $nowTime" +"%Y-%m-%d %H:%M:%S"`
	echo 'staff: '"$endUserStaffNumber" > "$sftpUserInfo"
	echo 'mail: '"$userMail" >> "$sftpUserInfo"
	echo 'jr: '"$jrNumber" >> "$sftpUserInfo"
	echo 'ctime: '"$nowTime" >> "$sftpUserInfo"
	echo 'expires: '"$expires" >> "$sftpUserInfo"
	$0 passwd reset "$sftpAccountName" "$jrNumber" "$sftpPasswd"
	/usr/bin/chmod 600 "$sftpUserInfo"

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'User "'"$sftpAccountName"'" was created failed!'
		exit 1
	else
		echo 'User "'"$sftpAccountName"'" was created successfully!'
		changeMsg='addUser "''jr:'"$jrNumber"' account:'"$sftpAccountName"' staff:'"$endUserStaffNumber"' mail:'"$userMail"' expires:'"$expires"'"'
		if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
	fi
	echo ''
	echo 'User details see below,'
	echo '#------------------------------------------------'
	$0 user get "$sftpAccountName"
	echo ''
	echo '#------------------------------------------------'
	for ((;;)); do
		echo 'Please choose a login type,'
		read -p 'Continue with (k/K) for key file authentication or (p/P) for password authentication(default key file): ' choice
		case "$choice" in
			k|K )
				loginType="keyfile"
				echo "Login Type: Key file"
				break
		        	;;
			p|P )
				loginType="password"
				echo "Login Type: Username and password"
				break
				;;
			"$Na" )
				loginType="keyfile"
				echo "Login Type: Key file"
				break
		        	;;
			* )
				echo "invalid!"
				;;
		esac
	done
	echo ''
	echo '#------------------------------------------------'
	for ((;;)); do
		if [ "$loginType" == "keyfile" ]; then
			read -p 'Send username and key file of "'"$sftpAccountName"'", Continue (y/n)?' choice
		else
			read -p 'Send username and password of "'"$sftpAccountName"'", Continue (y/n)?' choice
		fi
		case "$choice" in 
			y|Y )
				echo "yes"
				if [ "$loginType" == "keyfile" ]; then
					$0 ca send "$sftpAccountName"
				else
					$0 passwd send "$sftpAccountName"
				fi
				exit 0
		        	;;
			n|N )
				echo "no"
				exit 1
				;;
			* )
				echo "invalid!"
				;;
		esac
	done
}

getUser() {
	# Function implementation to get user list
	sftpAccountName="$parameter1"
	if [ "$sftpAccountName" == "" ]; then
		echo "Usage: $0 user get <list>"
		echo "       $0 user get <sftp account>"
		echo "       $0 user get <all>"
		echo "       $0 user get <root>"
		exit 1;
	fi

	sftpUserRootDir="$sftpDataDir"'/'"$sftpAccountName"
	sftpUserHomeDir="$sftpUserRootDir"'/'"$sftpHomeName"
	sftpUserKeysRootDir="$authorizedKeysRootDir"'/'"$sftpAccountName"
	sftpUserInfo="$sftpUserKeysRootDir"'/'"$sftpUserInfoFileName"
	sftpUserKeysDir="$sftpUserKeysRootDir"'/.ssh'

	if [ "$sftpAccountName" == "root" ]; then
		$0 home get root
		$0 ca get root
	fi

	if [ "$sftpAccountName" == "list" ]; then
		for i in `cat /etc/passwd | cut -d":" -f1`; do
			if [ `id $i | grep "$sftpGroupName" | wc -l` = 0 ]; then
				continue
			fi
			echo $i
		done
	fi

	if [ "$sftpAccountName" != "list" -a "$sftpAccountName" != "all" -a "$sftpAccountName" != "root" ]; then
        	if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
			echo 'User "'"$sftpAccountName"'" does not exist!'
			exit 1;
		fi
		userInfo=""
		if [ -f "$sftpUserInfo" ]; then
			userInfo=`cat "$sftpUserInfo"`
		else
			echo 'Error: User information file '"$sftpUserInfo"' is lost, please fix it manually!'
		fi
		echo 'SFTP Account: '"$sftpAccountName"
		echo 'SFTP Account Create Time: '`echo "$userInfo" | grep "ctime: " | sed 's/ctime: //g'`
		echo 'End User Staff: '`echo "$userInfo" | grep "staff: " | sed 's/staff: //g'`
		echo 'End User Initial Mail: '`echo "$userInfo" | grep "mail: " | sed 's/mail: //g'`
		echo 'End User JR: '`echo "$userInfo" | grep "jr: " | sed 's/jr: //g'`
		echo 'User OS ID: '`id "$sftpAccountName"`
		echo 'User Data Root: '"$sftpUserRootDir"
		echo 'User Home: '"$sftpUserHomeDir"
		$0 ca get "$sftpAccountName"
		$0 quota get "$sftpAccountName"
	fi

	if [ "$sftpAccountName" == "all" ]; then
		for i in `$0 user get list`; do
			$0 user get "$i"
			echo
		done
	fi
}

delUser() {
	# Function to delete user
	sftpAccountName="$parameter1"
	jrNumber="$parameter2"
	if [[ "$sftpAccountName" == "" || "$jrNumber" == "" ]]; then
		echo "Usage: $0 user del <sftp account> <JR No.>"
		exit 1;
	fi

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'User "'"$sftpAccountName"'" does not exist!'
		exit 1;
	fi

	jrNumber="`echo "$jrNumber" | tr 'a-z' 'A-Z'`"
	if ! checkJrRule "$jrNumber"; then
		echo 'JR number "'$jrNumber'" does not meet the rules!'
		exit 1;
	 fi

	sftpUserKeysRootDir="$authorizedKeysRootDir"'/'"$sftpAccountName"
	sftpUserInfo="$sftpUserKeysRootDir"'/'"$sftpUserInfoFileName"

	if [ ! -f "$sftpUserInfo" ]; then
		echo 'Could not find user user info file: '"$sftpUserInfo"
		exit 1
	fi
	endUserStaffNumber=`cat "$sftpUserInfo" | grep "staff: " | sed 's/staff: //g'`
	userMail=`cat "$sftpUserInfo" | grep "mail: " | sed 's/mail: //g'`
	ctime=`cat "$sftpUserInfo" | grep "ctime: " | sed 's/ctime: //g'`
	expires=`cat "$sftpUserInfo" | grep "expires: " | sed 's/expires: //g'`

	if [ `pgrep -u "$sftpAccountName" sshd | wc -l` != 0 ]; then
		echo ''
		echo '#------------------------------------------------'
		for ((;;)); do
			read -p 'User "'$sftpAccountName'" is still online, Continue (y/n)?' choice
			case "$choice" in
				y|Y )
					echo "yes"
					break
					;;
				n|N )
					echo "no"
					exit 1
					;;
				* )
					echo "invalid!"
					;;
			esac
		done
	fi
	echo ''
	echo '#------------------------------------------------'
	$0 ca del "$sftpAccountName" "$jrNumber"
	if [ -d "$sftpUserKeysRootDir" ]; then
		rm -rf "$sftpUserKeysRootDir"
	fi
	echo ''
	echo '#------------------------------------------------'
	$0 home del "$sftpAccountName" "$jrNumber"
	for ((;;)); do
		echo ''
		echo '#------------------------------------------------'
		read -p 'Remove system account of "'$sftpAccountName'", Continue (y/n)?' choice
		case "$choice" in 
			y|Y )
				echo "yes"
				for ((;;)); do
					if [ `pgrep -u "$sftpAccountName" sshd | wc -l` != 0 ]; then
						for i in `pgrep -u "$sftpAccountName" sshd`; do kill $i; done
						sleep 0.1
					else
						break
					fi
				done
				userdel "$sftpAccountName"
        			if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
					echo 'Successfully!'
					changeMsg='delUser "''jr:'"$jrNumber"' account:'"$sftpAccountName"' staff:'"$endUserStaffNumber"' mail:'"$userMail"' ctime:'"$ctime"' expires:'"$expires"'"'
					if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
					exit 0
				else
					echo 'Failed, please try again!'
				fi
		        	;;
			n|N )
				echo "no"
				exit 1
				;;
			* )
				echo "invalid!"
				continue
				;;
		esac
	done
	return 0
}

resetUserPasswd() {
	#Function to add user password
	sftpAccountName="$parameter1"
	jrNumber="$parameter2"
	sftpPasswd="$parameter3"

	if [ "$jrNumber" == "" ] || [ "$sftpAccountName" == "" ]; then
		echo "Usage: $0 user add <sftp account> <JR No.> [sftp passwd]"
		exit 1;
	fi

	jrNumber="`echo "$jrNumber" | tr 'a-z' 'A-Z'`"

	if ! checkJrRule "$jrNumber"; then
		echo 'JR number "'$jrNumber'" does not meet the rules!'
		exit 1
	fi

        sftpUserKeysRootDir="$authorizedKeysRootDir"'/'"$sftpAccountName"
	sftpUserInfo="$sftpUserKeysRootDir"'/'"$sftpUserInfoFileName"

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'Please create user "'"$sftpAccountName"'" first!'
		exit 1;
	fi

	if [ "$sftpPasswd" == "" ]; then
		sftpPasswd=`mkpasswd -l 10`
	fi
	echo "$sftpPasswd" | passwd --stdin "$sftpAccountName"

	userPasswordSave=`cat "$sftpUserInfo" | grep "userPassword: " | sed 's/userPassword: //g'`
	sftpPasswdSave=`echo "$sftpPasswd" | base64 -i`
	if [ "$userPasswordSave" == "" ]; then
		echo 'userPassword: '"$sftpPasswdSave" >> "$sftpUserInfo"
	else
		sed -i "s/$userPasswordSave/$sftpPasswdSave/g" "$sftpUserInfo"		
	fi

	userPasswordSave=`cat "$sftpUserInfo" | grep "userPassword: " | sed 's/userPassword: //g'`
        if [ "$userPasswordSave" == "" ]; then
		echo 'User "'"$sftpAccountName"'" password was created failed!'
		exit 1
	else
		echo 'User "'"$sftpAccountName"'" password was created successfully!'
		changeMsg='addUserPasswd "''jr:'"$jrNumber"' account:'"$sftpAccountName"' userPassword:******'
		if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
	fi

}

sendUserPasswd() {
	#Function to send user password to user

	sftpAccountName="$parameter1"
	sftpUserName="$parameter2"
	sftpUserMail="$parameter3"

	if [ "$sftpAccountName" == "" ]; then
		echo "Usage: $0 passwd send <sftp account> [userName] [userMail]"
		exit 1;
	fi

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'User "'"$sftpAccountName"'" does not exist!'
		exit 1;
	fi

	sftpUserKeysRootDir="$authorizedKeysRootDir"'/'"$sftpAccountName"
	sftpUserKeysDir="$sftpUserKeysRootDir"'/.ssh'
	sftpUserInfo="$sftpUserKeysRootDir"'/'"$sftpUserInfoFileName"

	if [ ! -f "$sftpUserInfo" ]; then
		echo 'Could not find user user info file: '"$sftpUserInfo"
		exit 1
	fi

	sftpUserMail=`cat "$sftpUserInfo" | grep "mail: " | sed 's/mail: //g'`
	if [ "$sftpUserMail" == "" ]; then
		read -p 'Please enter email address of account "'"$sftpAccountName"'": ' mailTo
	else
		mailTo="$sftpUserMail"
	fi
	if ! checkMailRule "$mailTo"; then
		echo 'Email address "'$mailTo'" does not meet the rules!'
		exit 1
	fi

	jrNumber=`cat "$sftpUserInfo" | grep "jr: " | sed 's/jr: //g'`
	if [ "$jrNumber" == "" ]; then
		read -p 'Please enter JR Number of user "'"$sftpAccountName"'": ' var
		jrNumber="`echo $var | tr 'a-z' 'A-Z'`"
	fi
	if ! checkJrRule "$jrNumber"; then
		echo 'JR number "'$jrNumber'" does not meet the rules!'
		exit 1
	fi
	endUserStaffNumber=`cat "$sftpUserInfo" | grep "staff: " | sed 's/staff: //g'`
	userName=`$0 ldap get "$endUserStaffNumber" cn | grep "cn: " | sed 's/cn: //g'`
	userPasswordSave=`cat "$sftpUserInfo" | grep "userPassword: " | sed 's/userPassword: //g'`
	userPassword=`echo "$userPasswordSave" | base64 -d`

	if [ "$userName" == "" ]; then
		read -p 'Please enter user name of user "'"$sftpAccountName"'": ' var
		userName="`echo $var | tr 'a-z' 'A-Z'`"
	fi

	shadowSalt=`grep "$sftpAccountName" /etc/shadow | cut -d":" -f2 | cut -d'$' -f3`
	typePasswordHash=`echo "$userPassword" | openssl passwd -6 -stdin -salt "$shadowSalt"`
	shadowPasswordHash=`grep "$sftpAccountName" /etc/shadow | cut -d":" -f2`
	if [ "$typePasswordHash" != "$shadowPasswordHash" ]; then
		echo 'Sending User "'"$sftpAccountName"'" password not match OS password, please update and tryi again!'
		exit 1
	fi

	echo ''
	echo '#------------------------------------------------'
	echo 'End User Name: '"$userName"
	echo 'End User Mail: '"$mailTo"
	echo 'JR: '"$jrNumber"
	echo 'SFTP Account: '"$sftpAccountName"
	for ((;;)); do
		read -p 'Confirm user information, Continue (y/n)?' choice
		case "$choice" in 
			y|Y )
				echo "yes"
				break
		        	;;
			n|N )
				echo "no"
				exit 1
				;;
			* )
				echo "invalid!"
				;;
		esac
	done

	mailSubject='[SFTP Service] SFTP account is ready – ['"$jrNumber"']'
	cat <<-EOF | mail -s "$mailSubject" -r "$mailFrom" "$mailTo"
	Dear $userName

	The SFTP account has been successfully created with the JR:$jrNumber. Please use the below username and password for SFTP services and keep confidential.

	Username: $sftpAccountName
	Password: $userPassword

	Please refer to the detailed User Guide below.

	https://pvtcloud.cmdschool.org/index.php/s/dx7ry7LFaStADDc

	You may contact IT HelpDesk, if you need further assistance or queries. 
	IT Helpdesk: (xx) xxxx

	Note: This email is an automatically generated email from [SFTP Service], please do not respond to this email, and delete immediately after saving the credentials!

	EOF
	if [ "$?" == "0" ]; then
		echo "successfully!"
		changeMsg='sendUserPasswd "''jr:'"$jrNumber"' account:'"$sftpAccountName"' userTo:'"$userName"' mailTo:'"$mailTo"'"'
		if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
	fi
	return 0
}

addUserHome() {
	# Function to create user home directory
	sftpAccountName="$parameter1"
	jrNumber="$parameter2"

	if [[ "$sftpAccountName" == "" || "$jrNumber" == "" ]]; then
		echo "Usage: $0 home add <sftp account> <JR No.>"
		exit 1;
	fi

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'User "'"$sftpAccountName"'" does not exist!'
		exit 1;
	fi

	jrNumber="`echo "$jrNumber" | tr 'a-z' 'A-Z'`"
	if ! checkJrRule "$jrNumber"; then
		echo 'JR number "'$jrNumber'" does not meet the rules!'
		exit 1;
	fi

	sftpUserRootDir="$sftpDataDir"'/'"$sftpAccountName"
	sftpUserHomeDir="$sftpUserRootDir"'/'"$sftpHomeName"

        if [ -d "$sftpUserRootDir" ]; then
		echo 'The user "'"$sftpAccountName"'" directory already exists, please backup and remove it first!'
		echo "$sftpUserRootDir"
		exit 1;
	fi

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'Please create user "'"$sftpAccountName"'" first!'
		exit 1;
	fi

	mkdir -p "$sftpUserHomeDir"
	chown root:root "$sftpUserRootDir"
	chmod -R 755 "$sftpUserRootDir"
	chown "$sftpAccountName":"$sftpGroupName" "$sftpUserHomeDir"
        if [ -d $sftpUserHomeDir ]; then
		changeMsg='addUserHome "''jr:'"$jrNumber"' account:'"$sftpAccountName"' home:'"$sftpUserHomeDir"'"'
		if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
	fi
}

delUserHome() {
	# Function to delete the user's home directory
	sftpAccountName="$parameter1"
	jrNumber="$parameter2"

	if [[ "$sftpAccountName" == "" || "$jrNumber" == "" ]]; then
		echo "Usage: $0 home del <sftp account> <JR No.>"
		exit 1;
	fi

	sftpUserRootDir="$sftpDataDir"'/'"$sftpAccountName"

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'User "'"$sftpAccountName"'" does not exist!'
		exit 1;
	fi

        if [ ! -d "$sftpUserRootDir" ]; then
		echo 'The directory of user "'"$sftpAccountName"'" not found, the program exits!'
		exit 1;
	fi

	jrNumber="`echo "$jrNumber" | tr 'a-z' 'A-Z'`"
	if ! checkJrRule "$jrNumber"; then
		echo 'JR number "'$jrNumber'" does not meet the rules!'
		exit 1;
	fi

	read -p 'Remove directory of "'"$sftpUserRootDir"'", Continue (y/n)?' choice
	case "$choice" in 
		y|Y )
			echo "yes"
			$0 mount del "$sftpAccountName" all "$jrNumber"
			if [ -f "$mailBox"'/'"$sftpAccountName" ]; then
				rm -f "$mailBox"'/'"$sftpAccountName"
			fi
			if [ -d "$sftpUserRootDir" ]; then
				rm -rf "$sftpUserRootDir"
			fi
        		if [ -d "$sftpUserRootDir" ]; then
				echo 'Failed, please try again!'
				exit 1
			else
                		echo 'Successfully!'
				changeMsg='delUserHome "''jr:'"$jrNumber"' account:'"$sftpAccountName"' root:'"$sftpUserRootDir"'"'
				if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
				return 0
        		fi
		        ;;
		n|N )
			echo "no"
			exit 1
			;;
		* )
			echo "invalid!"
			exit 1
			;;
	esac
}

getUserHome() {
	# Function implementation to query user home directory
	sftpAccountName="$parameter1"
	if [ "$sftpAccountName" == "" ]; then
		echo "Usage: $0 home get <list>"
		echo "       $0 home get <sftp account>"
		echo "       $0 home get <all>"
		echo "       $0 home get <root>"
		exit 1;
	fi

	sftpUserRootDir="$sftpDataDir"'/'"$sftpAccountName"
	sftpUserHomeDir="$sftpUserRootDir"'/'"$sftpHomeName"

	if [ "$sftpAccountName" == "root" ]; then
		echo 'Home Root Directory Path: '"$sftpDataDir"
		echo 'Home Root Directory Space: '`du -sh "$sftpDataDir" | awk  -F ' '  '{print $1}'`
	fi

	if [ "$sftpAccountName" == "list" ]; then
		ls -d "$sftpDataDir"'/'*
	fi

	if [ "$sftpAccountName" != "root" -a "$sftpAccountName" != "list" -a "$sftpAccountName" != "all" ]; then
        	if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
			echo 'User "'"$sftpAccountName"'" does not exist!'
			exit 1;
		fi
		echo 'User Home Directory Path: '"$sftpUserHomeDir"
		echo 'User Home Directory Space: '`du -sh "$sftpUserHomeDir" | awk  -F ' '  '{print $1}'`
	fi

	if [ "$sftpAccountName" == "all" ]; then
		for i in `$0 user get list`; do
			$0 home get "$i"
			echo
		done
	fi
}

addUserCA() {
	# Function to create a user's certificate.
	sftpAccountName="$parameter1"
	jrNumber="$parameter2"
	caPasswd="$parameter3"

	if [[ "$sftpAccountName" == "" || "$jrNumber" == "" ]]; then
		echo "Usage: $0 ca add <sftp account> <JR No.> [CA passwd]"
		exit 1;
	fi

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'User "'"$sftpAccountName"'" does not exist!'
		exit 1;
	fi

	jrNumber="`echo "$jrNumber" | tr 'a-z' 'A-Z'`"
	if ! checkJrRule "$jrNumber"; then
		echo 'JR number "'$jrNumber'" does not meet the rules!'
		exit 1;
	fi

	sftpUserKeysRootDir="$authorizedKeysRootDir"'/'"$sftpAccountName"
	sftpUserKeysDir="$sftpUserKeysRootDir"'/.ssh'

        if [ -d "$sftpUserKeysDir" ]; then
                echo 'The user "'"$sftpUserKeysDir"'" authorized Keys directory already exists, please backup and remove it first!'
                echo "$sftpUserKeysDir"
                exit 1;
        fi

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'Please create user "'"$sftpAccountName"'" first!'
		exit 1;
	fi

	mkdir -p "$sftpUserKeysDir"
	chown "$sftpAccountName":"$sftpGroupName" "$sftpUserKeysDir"
	chmod 700 "$sftpUserKeysDir"
	cd "$sftpUserKeysDir"
	if [ "$caPasswd" == "" ]; then	
		ssh-keygen -t rsa -P "" -f "$sftpAccountName"'_rsa'
	else
		ssh-keygen -t rsa -P "$caPasswd" -f "$sftpAccountName"'_rsa'
	fi
	cat "$sftpAccountName"'_rsa.pub' > "$authorizedKeysName"
	chmod 600 "$authorizedKeysName"
	chown "$sftpAccountName":"$sftpGroupName" "$authorizedKeysName"
	echo "$caPasswd" > old-passphrase
	puttygen --old-passphrase=old-passphrase -O private "$sftpAccountName"'_rsa' -o "$sftpAccountName"'_rsa.ppk'
	puttygen --old-passphrase=old-passphrase -O private "$sftpAccountName"'_rsa' -o "$sftpAccountName"'_rsa_v2.ppk' --ppk-param version=2
	rm -f old-passphrase
	echo 'Created successfully!'
	echo ''
	echo 'Certificate storage directory: '"$sftpUserKeysDir"
	echo 'Certificate name: '`ls "$sftpUserKeysDir"`
	echo ''
	echo 'Notice: '
	echo "$authorizedKeysName"' is the public key file authenticated by the sftp server (deleted users cannot login)'
	echo "$sftpAccountName"'.ppk is for the FileZilla client private key (should be sent to the user)'
	echo "$sftpAccountName"'_rsa is the private key for Linux sftp client (should be sent to the user)'
	echo "$sftpAccountName"'_rsa.pub is '"$authorizedKeysName"' file backup'
        if [ -f "$sftpUserKeysDir"'/'"$authorizedKeysName" ]; then
		changeMsg='addUserCA "''jr:'"$jrNumber"' account:'"$sftpAccountName"' ca:'"$sftpUserKeysDir"'/'"$authorizedKeysName"'"'
		if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
	fi
	return 0
}

delUserCA() {
	# Function to delete user certificate.
	sftpAccountName="$parameter1"
	jrNumber="$parameter2"

	if [[ "$sftpAccountName" == "" || "$jrNumber" == "" ]]; then
		echo "Usage: $0 ca del <sftp account> <JR No.>"
		exit 1;
	fi

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'User '"$sftpAccountName"' certificate directory not found!'
		exit 1;
	fi
        if [ -d "$sftpUserKeysRootDir" ]; then
		echo 'Certificate directory '"$sftpUserKeysRootDir"' does not exis!'
        fi

	jrNumber="`echo "$jrNumber" | tr 'a-z' 'A-Z'`"
	if ! checkJrRule "$jrNumber"; then
		echo 'JR number "'$jrNumber'" does not meet the rules!'
		exit 1;
	fi

	sftpUserKeysRootDir="$authorizedKeysRootDir"'/'"$sftpAccountName"
	sftpUserKeysDir="$sftpUserKeysRootDir"'/.ssh'

	for ((;;)); do
		read -p 'Remove user certificate of "'"$sftpAccountName"'", Continue (y/n)?' choice
		case "$choice" in 
			y|Y )
				echo "yes"
        			if [ -d "$sftpUserKeysDir" ]; then
                			rm -rf "$sftpUserKeysDir"
        			fi
        			if [ -d "$sftpUserKeysDir" ]; then
					echo 'Failed, please try again!'
					break
				else
                			echo 'Successfully!'
					changeMsg='delUserCA "''jr:'"$jrNumber"' account:'"$sftpAccountName"' keyroot:'"$sftpUserKeysDir"'"'
					if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
					break
        			fi
		        	;;
			n|N )
				echo "no"
				break
				;;
			* )
				echo "invalid!"
				continue
				;;
		esac
	done
	return 0
}

resetUserCA() {
	#Function to delete the certificate and recreate it.
	sftpAccountName="$parameter1"
	jrNumber="$parameter2"
	sftpPasswd="$parameter3"

	if [[ "$sftpAccountName" == "" || "$jrNumber" == "" ]]; then
		echo "Usage: $0 ca reset <sftp account> <JR No.> [sftp passwd]"
		exit 1;
	fi

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'User "'"$sftpAccountName"'" does not exist!'
		exit 1;
	fi

	jrNumber="`echo "$jrNumber" | tr 'a-z' 'A-Z'`"
	if ! checkJrRule "$jrNumber"; then
		echo 'JR number "'$jrNumber'" does not meet the rules!'
		exit 1;
	fi

	$0 ca del "$sftpAccountName" "$jrNumber"
	if [ "$?" == "0" ]; then
		$0 ca add "$sftpAccountName" "$jrNumber" "$sftpPasswd"
	fi
}

getUserCA() {
	# Function implementation to get user certificate
	sftpAccountName="$parameter1"
	if [ "$sftpAccountName" == "" ]; then
		echo "Usage: $0 ca get <list>"
		echo "       $0 ca get <sftp account>"
		echo "       $0 ca get <all>"
		echo "       $0 ca get <root>"
		exit 1;
	fi

	sftpUserRootDir="$sftpDataDir"'/'"$sftpAccountName"
	sftpUserHomeDir="$sftpUserRootDir"'/'"$sftpHomeName"
	sftpUserKeysRootDir="$authorizedKeysRootDir"'/'"$sftpAccountName"
	sftpUserKeysDir="$sftpUserKeysRootDir"'/.ssh'

	if [ "$sftpAccountName" == "root" ]; then
		echo 'Certificate Root Directory Path: '"$authorizedKeysRootDir"
		echo 'Certificate Root Directory Space: '`du -sh "$authorizedKeysRootDir" | awk  -F ' '  '{print $1}'`
	fi

	if [ "$sftpAccountName" == "list" ]; then
		ls -d "$authorizedKeysRootDir"'/'*'/.ssh/'
	fi

	if [ "$sftpAccountName" != "list" -a "$sftpAccountName" != "root" -a "$sftpAccountName" != "all" ]; then
        	if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
			echo 'User "'"$sftpAccountName"'" does not exist!'
			exit 1;
		fi
		if [ -d "$sftpUserKeysDir" ]; then
			echo 'Certificate Storage Directory: '"$sftpUserKeysDir"
		else
			echo 'Error: SFTP user CA directory '"$sftpUserKeysDir"' is lost, please fix it manually!'
		fi
		$0 ca expire "$sftpAccountName"
		echo 'Authentication Public Key: '"$sftpUserKeysDir"'/'"$authorizedKeysName"
		echo 'Backup Public Key: '"$sftpUserKeysDir"'/'"$sftpAccountName"'_rsa.pub'
		echo 'Linux SFTP Private Key: '"$sftpUserKeysDir"'/'"$sftpAccountName"'_rsa'
		echo 'FileZilla Private Key: '"$sftpUserKeysDir"'/'"$sftpAccountName"'_rsa.ppk'
		echo 'FileZilla Private Key Version 2: '"$sftpUserKeysDir"'/'"$sftpAccountName"'_rsa_v2.ppk'
	fi

	if [ "$sftpAccountName" == "all" ]; then
		for i in `$0 user get list`; do
			$0 ca get "$i"
			echo
		done
	fi
}

expireUserCA() {
	# Function to realize user certificate expiration date management
	sftpAccountName="$parameter1"
	sftpCMD="$parameter2"
	endUserStaffNumber="$parameter3"
	jrNumber="$parameter4"

	if [[ "$sftpAccountName" == "" || "$sftpCMD" == "+"* || "$sftpCMD" == "-"* ]]; then
		if [[ "$sftpAccountName" == "" || "$endUserStaffNumber" == "" || "$jrNumber" == "" ]]; then
			echo "Usage: $0 ca expire <sftp account>"
			echo "       $0 ca expire <sftp account> <+integer> <endUser staff No.> <JR No.>"
			echo "       $0 ca expire <sftp account> <-integer> <endUser staff No.> <JR No.>"
			echo "       $0 ca expire <sftp account> <check>"
			echo "       $0 ca expire <sftp account> <flush>"
			echo "       $0 ca expire <all> <check>"
			echo "       $0 ca expire <all> <flush>"
			exit 1;
		fi
	fi

	if [ "$sftpAccountName" != "all" ]; then
        	if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
			echo 'User "'"$sftpAccountName"'" does not exist!'
			exit 1;
		fi
	fi

	endUserStaffNumber="`echo "$endUserStaffNumber" | tr 'a-z' 'A-Z'`"

	sftpUserRootDir="$sftpDataDir"'/'"$sftpAccountName"
	sftpUserHomeDir="$sftpUserRootDir"'/'"$sftpHomeName"
	sftpUserKeysRootDir="$authorizedKeysRootDir"'/'"$sftpAccountName"
	sftpUserKeysDir="$sftpUserKeysRootDir"'/.ssh'
	sftpUserInfo="$sftpUserKeysRootDir"'/'"$sftpUserInfoFileName"

	userInfo=""
	if [ "$sftpAccountName" != "all" ]; then
		if [ -f "$sftpUserInfo" ]; then
			userInfo=`cat "$sftpUserInfo"`
		else
			echo 'Error: User information file '"$sftpUserInfo"' is lost, please fix it manually!'
		fi
	fi
	infoExpires=`echo "$userInfo" | grep "expires: " | sed 's/expires: //g'`
	infoJrNumber=`echo "$userInfo" | grep "jr: " | sed 's/jr: //g'`
	infoEndUserStaffNumber=`echo "$userInfo" | grep "staff: " | sed 's/staff: //g'`
	infoUserMail=`echo "$userInfo" | grep "mail: " | sed 's/mail: //g'`

	formatNow=`date -d "$nowTime" +%s`
	formatExpires=`date -d "$infoExpires" +%s`
	expireDays="$((($formatExpires - $formatNow)/86400))"


	# show user ca expire
	if [[ "$sftpAccountName" != "all" && "$sftpCMD" == "" && "$sftpCMD" != "+"* && "$sftpCMD" != "-"* ]]; then
        	if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
			echo 'User "'"$sftpAccountName"'" does not exist!'
			exit 1;
		fi
		if [ ! -d "$sftpUserKeysDir" ]; then
			echo 'Error: SFTP user CA directory '"$sftpUserKeysDir"' is lost, please fix it manually!'
		fi
		echo 'Certificate Expires: '"$infoExpires"
	fi

	# edit user ca expire
	if [[ "$sftpAccountName" != "all" && "$sftpCMD" == "+"* || "$sftpCMD" == "-"* ]]; then
		userMail=`$0 ldap get "$endUserStaffNumber" "mail" | sed 's/mail: //g'`
		abnormal="0"	
		if ! checkMailRule "$userMail"; then
			echo 'The format of the automatically obtained mail '"$userMail"' address is abnormal!'
			abnormal="1"
		fi
		if [ "$abnormal" == "1" ]; then
			read -p 'Please enter the mail address of user "'"$endUserStaffNumber"'" :' userMail
		fi
		if ! checkMailRule "$userMail"; then
			echo 'Email address "'$userMail'" does not meet the rules!'
			exit 1
		fi
		jrNumber="`echo "$jrNumber" | tr 'a-z' 'A-Z'`"
		if ! checkJrRule "$jrNumber"; then
			echo 'JR number "'$jrNumber'" does not meet the rules!'
			exit 1;
		fi

		if [ "$infoJrNumber" = "$jrNumber" ]; then
			echo 'JR number "'$jrNumber'" already exists, the operation is canceled!'
			exit 1
		fi
		sed -i "s/$infoJrNumber/$jrNumber/g" "$sftpUserInfo"
		expireTime=`date -d "$infoExpires" +%s`
		currentTime=`date -d "$nowTime" +%s`
		if [ "$currentTime" -gt "$expireTime" -a "$sftpCMD"=="+" ]; then
			newExpires=`date -d "$sftpCMD day $nowTime" +"%Y-%m-%d %H:%M:%S"`
		else
			newExpires=`date -d "$sftpCMD day $infoExpires" +"%Y-%m-%d %H:%M:%S"`
		fi
		if [ "$infoExpires" != "$newExpires" ]; then
			sed -i "s/$infoExpires/$newExpires/g" "$sftpUserInfo"
		fi
		if [ "$infoEndUserStaffNumber" != "$endUserStaffNumber" ]; then
			sed -i "s/$infoEndUserStaffNumber/$endUserStaffNumber/g" "$sftpUserInfo"
		fi
		if [ "$infoUserMail" != "$userMail" ]; then
			sed -i "s/$infoUserMail/$userMail/g" "$sftpUserInfo"
		fi
		$0 ca expire "$sftpAccountName"
		changeMsg='expire-changeExpireUserCA "''jr:'"$jrNumber"' account:'"$sftpAccountName"' staff:'"$endUserStaffNumber"' mail:'"$userMail"' expires:'"$newExpires"'"'
		if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
	fi

	if [ "$sftpAccountName" != "all" -a "$sftpCMD" == "check" ]; then
		if [ ! -f "$sftpUserInfo" ]; then
			echo 'Could not find user user info file: '"$sftpUserInfo"
			exit 1
		fi
		if [ "$expireDays" -gt "$alertDays" ]; then
			exit 0
		fi
		flag="0"
		for i in $(seq $alertDays -$alertFrequency $alertFrequency); do
			if [ "$expireDays" != "$i" ]; then
				continue
			fi
			flag="1"
		done
		senMsg='Send '"$expireDays"'-day extension notice to user '"$sftpAccountName"'.'
		if [ `egrep "$(date '+%Y-%m-%d')|$(date '+%Y-%m-%d' -d '-1 day')" "$logAlert" | grep "$senMsg" | wc -l` != "0" ]; then
			exit 0
		fi
		if [ "$flag" == "0" ]; then
			exit 0
		fi

		userName=`$0 ldap get "$infoEndUserStaffNumber" cn | grep "cn: " | sed 's/cn: //g'`
		ldapUserMail=`$0 ldap get "$infoEndUserStaffNumber" mail | grep "mail: " | sed 's/mail: //g'`

		if [ "$infoUserMail" == "$ldapUserMail" ]; then
			sftpUserMail="$infoUserMail"
		else
			sftpUserMail="$ldapUserMail"
		fi
		mailTo="$sftpUserMail"
		if ! checkMailRule "$mailTo"; then
			echo 'Email address "'$mailTo'" does not meet the rules!' | tee -a "$logMessage"
			exit 1
		fi
		if [ "$userName" == "" ]; then
			echo 'User Name "'$userName'" does not meet the rules!' | tee -a "$logMessage"
			exit 1
		fi

		mailSubject='[SFTP Service] SFTP account extension notice'
		cat <<-EOF | mail -s "$mailSubject" -r "$mailFrom" "$mailTo"
		Dear $userName

		Your SFTP account "$sftpAccountName" will expiry on $infoExpires. Please submit IT JR for account renewal if necessary. Otherwise the account will be disabled without any further notice. Thanks!

		You may contact IT HelpDesk, if you need further assistance or queries. 
		IT Helpdesk: (xx) xxxx

		Note: This email is an automatically generated email from [SFTP Service], please do not respond to this email.
		EOF
		if [ "$?" == "0" ]; then
			echo "$nowTime"' '"$senMsg" | tee -a "$logAlert"
			echo "successfully!"
			changeMsg='expire-sendAlertMail "''jr:'"$infoJrNumber"' account:'"$sftpAccountName"' userTo:'"$userName"' mailTo:'"$mailTo"' expiry:'"$infoExpires"'"'
			if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
		fi
		return 0
	fi

	if [ "$sftpAccountName" == "all" -a "$sftpCMD" == "check" ]; then
		for i in `$0 user get list`; do
			$0 ca expire "$i" check
		done
	fi

	if [ "$sftpAccountName" != "all" -a "$sftpCMD" == "flush" ]; then
		if [ "$formatNow" -ge "$formatExpires" ]; then
			flag=`grep ^# "$sftpUserKeysDir"'/'"$authorizedKeysName" | wc -l`
			if [ "$flag" != "0" ]; then
				echo 'No flush '"$sftpAccountName"'!'
				return 0
			fi
			sed -i "s/^/#/g" "$sftpUserKeysDir"'/'"$authorizedKeysName"
			flag=`grep ^# "$sftpUserKeysDir"'/'"$authorizedKeysName" | wc -l`
			if [ "$flag" != "0" ]; then
				echo 'Flush '"$sftpAccountName"', disable user CA!'
				changeMsg='expire-disableUserCA "''jr:'"$infoJrNumber"' account:'"$sftpAccountName"' expiry:'"$infoExpires"'"'
				if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
				return 0
			else
				echo 'Failed, please try again!'
				exit 1
			fi
		else
			flag=`grep ^# "$sftpUserKeysDir"'/'"$authorizedKeysName" | wc -l`
			if [ "$flag" == "0" ]; then
				echo 'No flush '"$sftpAccountName"'!'
				return 0
			fi
			sed -i "s/^#//g" "$sftpUserKeysDir"'/'"$authorizedKeysName"
			flag=`grep ^# "$sftpUserKeysDir"'/'"$authorizedKeysName" | wc -l`
			if [ "$flag" == "0" ]; then
				echo 'Flush '"$sftpAccountName"', enable User CA!'
				changeMsg='expire-enableUserCA "''jr:'"$infoJrNumber"' account:'"$sftpAccountName"' expiry:'"$infoExpires"'"'
				if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
				return 0
			else
				echo 'Failed, please try again!'
				exit 1
			fi
		fi

	fi

	if [ "$sftpAccountName" == "all" -a "$sftpCMD" == "flush" ]; then
		for i in `$0 user get list`; do
			$0 ca expire "$i" flush
		done
	fi
}

setQuota() {
	# Function to realize user disk quota
	sftpAccountName="$parameter1"
	jrNumber="$parameter2"
	sftpQuota="$parameter3"

	if [[ "$sftpAccountName" == "" || "$jrNumber" == "" ]]; then
		echo "Usage: $0 quota set <sftp account> <JR No.> [quota]"
		exit 1;
	fi

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'Please create user "'"$sftpAccountName"'" first!'
		exit 1;
	fi

	jrNumber="`echo "$jrNumber" | tr 'a-z' 'A-Z'`"
	if ! checkJrRule "$jrNumber"; then
		echo 'JR number "'$jrNumber'" does not meet the rules!'
		exit 1;
	fi

	sftpUserRootDir="$sftpDataDir"'/'"$sftpAccountName"
	sftpUserHomeDir="$sftpUserRootDir"'/'"$sftpHomeName"

        if [ ! -d "$sftpUserRootDir" ]; then
		echo 'Please create user "'"$sftpAccountName"'" directory first,'
		echo "$sftpUserRootDir"
		exit 1;
	fi

	if [ "$sftpQuota" == "" ]; then
		sftpQuota="$defaultQuota"
	fi

	num=$(echo "$sftpQuota" | tr -cd '[0-9].')
	var=$(echo "$sftpQuota" | tr -d '[0-9].')
	case "$var" in
		[kK]|[kK][bB])
			sftpQuota=`echo "$num"`
			;;
		[mM]|[mM][bB])
			sftpQuota=`echo "$num * 1024" | bc`
		        ;;
		[gG]|[gG][bB])
			sftpQuota=`echo "$num * 1024 * 1024" | bc`
		        ;;
		[tT]|[tT][bB])
			sftpQuota=`echo "$num * 1024 * 1024 * 1024" | bc`
		        ;;
		*)
			echo "invalid!"
			exit 1
			;;
	esac
	setquota -u "$sftpAccountName" "$sftpQuota" "$sftpQuota" 0 0 "$quotaPath"
	changeMsg='setQuota "''jr:'"$jrNumber"' account:'"$sftpAccountName"' quota:'`echo "$sftpQuota / 1024 / 1024" | bc`'GB"'
	if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
	getQuota "$sftpAccountName"
	return 0
}

getQuota() {
	# Function to realize user disk quota
	sftpAccountName="$parameter1"
	if [ "$sftpAccountName" == "" ]; then
		echo "Usage: $0 quota get <all>"
		echo "       $0 quota get <sftp account>"
		echo "       $0 quota get <root>"
		exit 1;
	fi

	sftpUserRootDir="$sftpDataDir"'/'"$sftpAccountName"
	sftpUserHomeDir="$sftpUserRootDir"'/'"$sftpHomeName"

	if [ "$sftpAccountName" == "root" ]; then
		mountDir="`df -h | grep $quotaPath | awk -F ' ' '{print $6}'`"
		echo 'Quota Root Directory: '"$quotaPath"
		echo 'Quota Root Directory Space: '`du -sh "$mountDir" | awk  -F ' '  '{print $1}'`
	fi

	if [ "$sftpAccountName" != "root" -a "$sftpAccountName" != "all" ]; then
        	if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
			echo 'User "'"$sftpAccountName"'" does not exist!'
			exit 1;
		fi

        	if [ ! -d "$sftpUserRootDir" ]; then
			echo 'Please create user "'"$sftpAccountName"'" directory first,'
			echo "$sftpUserRootDir"
			exit 1;
		fi
		quotaMessage=`quota -u "$sftpAccountName" -s -w | grep $quotaPath`
		echo 'User Quota Directory: '"$sftpUserHomeDir"
		echo 'User Quota Space: '"`echo $quotaMessage | awk -F ' ' '{print $2}'`"
		echo 'User Quota: '"`echo $quotaMessage | awk -F ' ' '{print $3}'`"
		echo 'User Quota Limit: '"`echo $quotaMessage | awk -F ' ' '{print $4}'`"
	fi

	if [ "$sftpAccountName" == "all" ]; then
		for i in `$0 user get list`; do
			$0 quota get "$i"
			echo
		done
	fi
}

setMount() {
	#The function realizes mounting a user's data directory to another user-specified directory
	sftpAccountNameFrom="$parameter1"
	sftpAccountNameTo="$parameter2"
	jrNumber="$parameter3"
	writeEnable="$parameter4"

	if [[ "$sftpAccountNameFrom" == "" || "$sftpAccountNameTo" == "" || "$jrNumber" == "" ]]; then
		echo "Usage: $0 mount set <from sftp account> <to sftp account> <JR No.> [rw]"
		echo "       $0 mount set <from sftp account> <to sftp account> <JR No.> [ro]"
		exit 1;
	fi

        if [ `id "$sftpAccountNameFrom" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'Please create user "'"$sftpAccountNameFrom"'" first!'
		exit 1;
	fi

        if [ `id "$sftpAccountNameTo" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'Please create user "'"$sftpAccountNameTo"'" first!'
		exit 1;
	fi

        if [ "$sftpAccountNameFrom" == "$sftpAccountNameTo" ]; then
		echo "Do not allow yourself to mount yourself!"
		exit 1;
	fi

	jrNumber="`echo "$jrNumber" | tr 'a-z' 'A-Z'`"
	if ! checkJrRule "$jrNumber"; then
		echo 'JR number "'$jrNumber'" does not meet the rules!'
		exit 1;
	fi

	sftpUserRootDirFrom="$sftpDataDir"'/'"$sftpAccountNameFrom"
	sftpUserHomeDirFrom="$sftpUserRootDirFrom"'/'"$sftpHomeName"
	sftpUserRootDirTo="$sftpDataDir"'/'"$sftpAccountNameTo"

        if [ ! -d "$sftpUserRootDirFrom" ]; then
		echo 'Please create user "'"$sftpAccountNameFrom"'" directory first,'
		echo "$sftpUserRootDirFrom"
		exit 1;
	fi
        if [ ! -d "$sftpUserRootDirTo" ]; then
		echo 'Please create user "'"$sftpAccountNameTo"'" directory first,'
		echo "$sftpUserRootDirTo"
		exit 1;
	fi

        if [ "$writeEnable" == "" ]; then
		writeEnable="ro"
	fi

	mastConf="/- $autoSftpConf"
	if [ "`grep "^$mastConf" "$autoMastConf" | wc -l`" != "1" ]; then
		echo "$mastConf" >> "$autoMastConf"
	fi
	mountStr="$sftpUserRootDirTo/mount/$sftpAccountNameFrom -fstype=bind,$writeEnable :$sftpUserHomeDirFrom"
	grepMountStr="$sftpUserRootDirTo/mount/$sftpAccountNameFrom -fstype=bind,.* :$sftpUserHomeDirFrom"

	if [ "`grep "^$grepMountStr" "$autoSftpConf" | wc -l`" == "0" ]; then
		echo "$mountStr" >> "$autoSftpConf"
		systemctl reload autofs.service
		echo 'Mount "'"$sftpAccountNameFrom"'" home directory to "'"$sftpAccountNameTo"'" was created successfully!'
		changeMsg='setMount "''jr:'"$jrNumber"' mount:'"$sftpAccountNameFrom home directory to $sftpAccountNameTo"'"'
		if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
	else
		echo 'Mount "'"$sftpAccountNameFrom"'" home directory to "'"$sftpAccountNameTo"'" already exists!'
	fi
}

delMount() {
	#The function realizes mounting a user's data directory to another user-specified directory
	sftpAccountNameTo="$parameter1"
	sftpAccountNameFrom="$parameter2"
	jrNumber="$parameter3"

	if [[ "$sftpAccountNameFrom" == "" || "$sftpAccountNameTo" == "" || "$jrNumber" == "" ]]; then
		echo "Usage: $0 mount del <on sftp account> <from sftp account> <JR No.>"
		echo "       $0 mount del <on sftp account> <all> <JR No.>"
		exit 1;
	fi
       	if [[ "$sftpAccountNameFrom" != "all" && `id "$sftpAccountNameFrom" 2>&1 | grep "no such user" | wc -l` == 1 ]]; then
		echo 'Please create user "'"$sftpAccountNameFrom"'" first!'
		exit 1;
	fi

        if [ `id "$sftpAccountNameTo" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'Please create user "'"$sftpAccountNameTo"'" first!'
		exit 1;
	fi

	jrNumber="`echo "$jrNumber" | tr 'a-z' 'A-Z'`"
	if ! checkJrRule "$jrNumber"; then
		echo 'JR number "'$jrNumber'" does not meet the rules!'
		exit 1;
	fi

	sftpUserRootDirFrom="$sftpDataDir"'/'"$sftpAccountNameFrom"
	sftpUserHomeDirFrom="$sftpUserRootDirFrom"'/'"$sftpHomeName"
	sftpUserRootDirTo="$sftpDataDir"'/'"$sftpAccountNameTo"

        if [[ "$sftpAccountNameFrom" != "all" && ! -d "$sftpUserRootDirFrom" ]]; then
		echo 'Please create user "'"$sftpAccountNameFrom"'" directory first,'
		echo "$sftpUserRootDirFrom"
		exit 1;
	fi
        if [ ! -d "$sftpUserRootDirTo" ]; then
		echo 'Please create user "'"$sftpAccountNameTo"'" directory first,'
		echo "$sftpUserRootDirTo"
		exit 1;
	fi

	mountStr="$sftpUserRootDirTo/mount/$sftpAccountNameFrom -fstype=bind,.* :$sftpUserHomeDirFrom"
	uMountStr="$sftpUserRootDirTo/mount/$sftpAccountNameFrom"

	if [ "$sftpAccountNameFrom" != "all" ]; then
		if [ "`grep "^$mountStr" "$autoSftpConf" | wc -l`" -ge "1" ]; then
			sed -i "s#$mountStr##g" "$autoSftpConf"
			sed -i '/^$/d' "$autoSftpConf"
			systemctl reload autofs.service
			for ((;;)); do
				if [ "`mount | grep "$uMountStr" | wc -l`" -ge "1" ]; then
					umount -lf "$uMountStr" > /dev/null 2>&1
				else
					break
				fi
			done

			if [ -d "$uMountStr" ]; then
				rm -rf "$uMountStr"
			fi
			echo 'delMount "'"$sftpAccountNameFrom"'" on "'"$sftpAccountNameTo"'" was successfully!'
			changeMsg='delMount "''jr:'"$jrNumber"' mount:'"$sftpAccountNameFrom on $sftpAccountNameTo"'"'
			if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
		else
			echo 'delMount "'"$sftpAccountNameFrom"'" on "'"$sftpAccountNameTo"'" no found!'
		fi
	fi

	if [[ "$sftpAccountNameFrom" == "all" ]]; then
		$0 mount get "$sftpAccountNameTo" > /dev/null
		if [ $? == 0 ]; then
			for i in `$0 mount get "$sftpAccountNameTo"  | cut -d" " -f1 | awk -F '/'  '{print $(NF-1)}'`; do
				$0 mount del "$sftpAccountNameTo" "$i" "$jrNumber"
			done
		fi
	fi
}

getMount() {
	#The function realizes mounting a user's data directory to another user-specified directory
	sftpAccountNameTo="$parameter1"
	sftpAccountNameFrom="$parameter2"

	if [ "$sftpAccountNameTo" == "" ]; then
		echo "Usage: $0 mount get <all>"
		echo "       $0 mount get <on sftp account> [from sftp account]"
		exit 1;
	fi

	if [ "$sftpAccountNameTo" != "all" ]; then
        	if [ `id "$sftpAccountNameTo" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
			echo 'Please create user "'"$sftpAccountNameTo"'" first!'
			exit 1;
		fi

		sftpUserRootDirFrom="$sftpDataDir"'/'"$sftpAccountNameFrom"
		sftpUserHomeDirFrom="$sftpUserRootDirFrom"'/'"$sftpHomeName"
		sftpUserRootDirTo="$sftpDataDir"'/'"$sftpAccountNameTo"
		sftpUserHomeDirTo="$sftpUserRootDirTo"'/'"$sftpHomeName"

		if [ "$sftpAccountNameFrom" == "" ]; then
			mountStr="$sftpUserRootDirTo/mount/.* -fstype=bind,.* :.*"
		else
			mountStr="$sftpUserRootDirTo/mount/$sftpAccountNameFrom -fstype=bind,.* :$sftpUserHomeDirFrom"
		fi

		if [ "`grep "^$mountStr" "$autoSftpConf" | wc -l`" -lt "1" ]; then
			echo 'Mount point does not exist for user "'"$sftpAccountNameTo"'"'
			exit 1;
		else
			IFS=$'\n'
			for i in `grep "^$mountStr" "$autoSftpConf"`; do
				sftpUserHomeDirFrom=`echo "$i" | cut -d" " -f3 | sed 's~:~~g'`
				sftpUserHomeDirTo=`echo "$i" | cut -d" " -f1`
				rwStatus=`echo "$i" | cut -d" " -f2 | cut -d"," -f2`
				echo "$sftpUserHomeDirFrom on $sftpUserHomeDirTo ($rwStatus)"
			done
			exit 0;
		fi
	fi

	if [[ "$sftpAccountNameTo" = "all" ]]; then
		IFS=$'\n'
		for i in `cat "$autoSftpConf" | cut -d" " -f1`; do
			sftpAccountNameTo=`echo "$i" | awk -F '/'  '{print $(NF-2)}'`
			sftpAccountNameFrom=`echo "$i" | awk -F '/'  '{print $NF}'`
			$0 mount get "$sftpAccountNameTo" "$sftpAccountNameFrom"
		done
		return 0
	fi
}

bakUserCA() {
	#Function to manually back up user certificates.
	sftpAccountName="$parameter1"
	if [ "$sftpAccountName" == "" ]; then
		echo "Usage: $0 ca backup <sftp account>"
		exit 1;
	fi

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'User "'"$sftpAccountName"'" does not exist!'
		exit 1;
	fi

        if [ ! -d "$backupDir" ]; then
                echo 'Backup storage directory '"$backupDir"' does not exist'
                exit 1;
        fi

	sftpUserKeysRootDir="$authorizedKeysRootDir"'/'"$sftpAccountName"
	sftpUserKeysDir="$sftpUserKeysRootDir"'/.ssh'
	sftpKeysBackupName="$sftpAccountName"'_sftpd_authorized_keys-'`date +'%Y%m%d%H%M%S'`'.tar.bz2'
        if [ -d "$sftpUserKeysDir" ]; then
		tar cvjf "$backupDir"'/'"$sftpKeysBackupName" "$sftpUserKeysDir"
	else
                echo 'Backup directory '"$sftpUserKeysDir"' does not exist'
                exit 1;
        fi
	echo 'Backup successfully!'
	echo ''
	echo 'Backup storage directory: '"$backupDir"
	echo 'Backup file name:' 
	ls "$backupDir"'/'"$sftpKeysBackupName"
	echo ''
	echo 'Notice: '
	echo '"'"$sftpKeysBackupName"'" is sftp backup certificate'
	return 0
}

bakUserHome() {
	#Function to manually backup user home data.
	sftpAccountName="$parameter1"

	if [ "$sftpAccountName" == "" ]; then
		echo "Usage: $0 home backup <sftp account>"
		exit 1;
	fi

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'User "'"$sftpAccountName"'" does not exist!'
		exit 1;
	fi

	sftpUserRootDir="$sftpDataDir"'/'"$sftpAccountName"
	sftpUserHomeDir="$sftpUserRootDir"'/'"$sftpHomeName"

        if [ ! -d "$backupDir" ]; then
               	echo 'Backup storage directory '"$backupDir"' does not exist'
               	exit 1;
        fi

	sftpHomeBackupName="$sftpAccountName"'_sftpd_myhome_data-'`date +'%Y%m%d%H%M%S'`'.tar.bz2'
        if [ -d "$sftpUserHomeDir" ]; then
		tar cvjf "$backupDir"'/'"$sftpHomeBackupName" "$sftpUserHomeDir"
	else
               	echo 'Backup directory '"$sftpUserHomeDir"' does not exist'
               	exit 1;
        fi
        if [ -f "$backupDir"'/'"$sftpHomeBackupName" ]; then
		echo 'Backup successfully!'
		echo ''
		echo 'Backup storage directory: '"$backupDir"
		echo 'Backup file name:' 
		echo "$backupDir"'/'"$sftpHomeBackupName"
		echo ''
		echo 'Notice: '
		echo '"'"$sftpHomeBackupName"'" is sftp user home directory data'
	else
		echo 'Backup file '"$backupDir"'/'"$sftpHomeBackupName"' not found, backup failed!'
                exit 1;
        fi
	return 0
}

bakUser() {
	#Function to manually backup user home data.
	sftpAccountName="$parameter1"
	if [ "$sftpAccountName" == "" ]; then
		echo "Usage: $0 user backup <sftp account>"
		exit 1;
	fi

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'User "'"$sftpAccountName"'" does not exist!'
		exit 1;
	fi

        if [ ! -d "$backupDir" ]; then
                echo 'Backup storage directory '"$backupDir"' does not exist'
                exit 1;
        fi

	sftpUserKeysRootDir="$authorizedKeysRootDir"'/'"$sftpAccountName"
	sftpUserKeysDir="$sftpUserKeysRootDir"'/.ssh'
	sftpUserInfoPath="$sftpUserKeysRootDir"'/'"$sftpUserInfoFileName"
	sftpInfoBackupName="$sftpAccountName"'_sftpd_user_info-'`date +'%Y%m%d%H%M%S'`'.tar.bz2'

        if [ -f "$sftpUserInfoPath" ]; then
		tar cvjf "$backupDir"'/'"$sftpInfoBackupName" "$sftpUserInfoPath"
	else
               	echo 'Backup file '"$sftpUserInfoPath"' does not exist'
               	exit 1;
        fi
        if [ -f "$backupDir"'/'"$sftpInfoBackupName" ]; then
		echo 'Backup successfully!'
		echo ''
		echo 'Backup storage directory: '"$backupDir"
		echo 'Backup file name:' 
		echo "$backupDir"'/'"$sftpInfoBackupName"
		echo ''
		echo 'Notice: '
		echo '"'"$sftpInfoBackupName"'" is sftp user info data'
	else
		echo 'Backup file '"$backupDir"'/'"$sftpInfoBackupName"' not found, backup failed!'
                exit 1;
        fi
	echo ''
	echo '#------------------------------------------------'
	$0 ca backup "$sftpAccountName"
	echo ''
	echo '#------------------------------------------------'
	$0 home backup "$sftpAccountName"
	return 0
}

getBackup() {
	# Function implementation to get user list
	sftpAccountName="$parameter1"
	if [ "$sftpAccountName" == "" ]; then
		echo "Usage: $0 backup get <list>"
		echo "       $0 backup get <sftp account>"
		echo "       $0 backup get <all>"
		echo "       $0 backup get <root>"
		exit 1;
	fi

        if [ ! -d "$backupDir" ]; then
                echo 'Backup storage directory '"$backupDir"' does not exist'
                exit 1;
        fi

	if [ "$sftpAccountName" == "root" ]; then
		echo 'Backup Root Directory Path: '"$backupDir"
		echo 'Backup Root Directory Space: '`du -sh "$backupDir" | awk  -F ' '  '{print $1}'`
	fi

	if [ "$sftpAccountName" == "list" ]; then
		ls "$backupDir"'/'*'_sftpd_'*'.tar.bz2'
	fi

	if [ "$sftpAccountName" != "list" -a "$sftpAccountName" != "all" -a "$sftpAccountName" != "root" ]; then
        	if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
			echo 'User "'"$sftpAccountName"'" does not exist!'
			exit 1;
		fi
		listMessage=`ls "$backupDir"'/'"$sftpAccountName"'_sftpd_'*'.tar.bz2' 2>&1`
		if [ `echo "$listMessage" | grep "No such file or directory" | wc -l` == "0" ]; then
			echo "$listMessage"
		else
			exit 1;
		fi
	fi

	if [ "$sftpAccountName" == "all" ]; then
		for i in `$0 user get list`; do
			$0 backup get "$i"
			if [ "$?" == "0" ]; then
				echo
			fi
		done
	fi
}

recoverUserCA() {
	#Function to realize the recovery of user certificate
	sftpAccountName="$parameter1"
	jrNumber="$parameter2"

	if [[ "$sftpAccountName" == "" || "$jrNumber" == "" ]]; then
		echo "Usage: $0 ca recover <sftp account> <JR No.>"
		exit 1;
	fi

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'User "'"$sftpAccountName"'" does not exist!'
		exit 1;
	fi

	jrNumber="`echo "$jrNumber" | tr 'a-z' 'A-Z'`"
	if ! checkJrRule "$jrNumber"; then
		echo 'JR number "'$jrNumber'" does not meet the rules!'
		exit 1;
	fi

	sftpUserKeysRootDir="$authorizedKeysRootDir"'/'"$sftpAccountName"
	sftpUserKeysDir="$sftpUserKeysRootDir"'/.ssh'
	bakFiles=`ls "$backupDir"'/'"$sftpAccountName"'_sftpd_authorized_keys-'*'.tar.bz2'`

	echo 'Below actions will recover the user certificate directory, please select the backup file number to recover,'
	IFS=$'\n'
	select bakFile in $bakFiles; do
		read -p 'Overwrite direcotory "'"$sftpUserKeysDir"'", Continue (y/n)?' choice
		case "$choice" in 
		y|Y )
			echo "yes"
			if [ -f "$bakFile" ]; then
				tar xvf "$bakFile" -C /
				changeMsg='recoverUserCA "''jr:'"$jrNumber"' account:'"$sftpAccountName"' backupFile:'"$bakFile"'"'
				if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
			fi
			return 0
		        ;;
		n|N )
			echo "no"
			exit 1
			;;
		* )
			echo "invalid!"
			exit 1
			;;
		esac
		break
	done
	return 0
}

recoverUserHome() {
	#Function to realize the recovery of user home
	sftpAccountName="$parameter1"
	jrNumber="$parameter2"

	if [[ "$sftpAccountName" == "" || "$sftpAccountName" == "" ]]; then
		echo "Usage: $0 home recover <sftp account> <JR No.>"
		exit 1;
	fi

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'User "'"$sftpAccountName"'" does not exist!'
		exit 1;
	fi

	jrNumber="`echo "$jrNumber" | tr 'a-z' 'A-Z'`"
	if ! checkJrRule "$jrNumber"; then
		echo 'JR number "'$jrNumber'" does not meet the rules!'
		exit 1;
	fi

	sftpUserRootDir="$sftpDataDir"'/'"$sftpAccountName"
	sftpUserHomeDir="$sftpUserRootDir"'/'"$sftpHomeName"
	bakFiles=`ls "$backupDir"'/'"$sftpAccountName"'_sftpd_myhome_data-'*'.tar.bz2'`

	echo 'Below actions will recover the user home directory, please select the backup file number to recover,'
	IFS=$'\n'
	select bakFile in $bakFiles; do
		read -p 'Overwrite direcotory "'"$sftpUserHomeDir"'", Continue (y/n)?' choice
		case "$choice" in 
		y|Y )
			echo "yes"
			if [ -f "$bakFile" ]; then
				tar xvf "$bakFile" -C /
				changeMsg='recoverUserHome "''jr:'"$jrNumber"' account:'"$sftpAccountName"' backupFile:'"$bakFile"'"'
				if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
			fi
			return 0
		        ;;
		n|N )
			echo "no"
			exit 1
			;;
		* )
			echo "invalid!"
			exit 1
			;;
		esac
		break
	done
	return 0
}

recoverUser() {
	#Function to realize the recovery of user home
	sftpAccountName="$parameter1"
	jrNumber="$parameter2"

	if [[ "$sftpAccountName" == "" || "$jrNumber" == "" ]]; then
		echo "Usage: $0 user recover <sftp account> <JR No.>"
		exit 1;
	fi

	jrNumber="`echo "$jrNumber" | tr 'a-z' 'A-Z'`"
	if ! checkJrRule "$jrNumber"; then
		echo 'JR number "'$jrNumber'" does not meet the rules!'
		exit 1;
	fi

	sftpUserKeysRootDir="$authorizedKeysRootDir"'/'"$sftpAccountName"
	sftpUserKeysDir="$sftpUserKeysRootDir"'/.ssh'
	sftpUserInfoPath="$sftpUserKeysRootDir"'/'"$sftpUserInfoFileName"
	bakFiles=`ls "$backupDir"'/'"$sftpAccountName"'_sftpd_user_info-'*'.tar.bz2'`


        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'User "'"$sftpAccountName"'" does not exist!'
		read -p 'Recreate system account of "'$sftpAccountName'", Continue (y/n)?' choice
		case "$choice" in 
		y|Y )
			echo "yes"
			useradd "$sftpAccountName" -g "$sftpGroupName" -M -d '/'"$sftpHomeName" -s /bin/false
			echo "$sftpPasswd" | passwd --stdin "$sftpAccountName"
		        ;;
		n|N )
			echo "no"
			exit 1
			;;
		* )
			echo "invalid!"
			exit 1
			;;
		esac
		break
	fi
	echo ''
	echo '#------------------------------------------------'
	echo 'Below actions will recover the user information file, please select the backup file number to recover,'
	IFS=$'\n'
	select bakFile in $bakFiles; do
		read -p 'Overwrite file "'"$sftpUserInfoPath"'", Continue (y/n)?' choice
		case "$choice" in 
		y|Y )
			echo "yes"
			if [ -f "$bakFile" ]; then
				tar xvf "$bakFile" -C /
				changeMsg='recoverUser "''jr:'"$jrNumber"' account:'"$sftpAccountName"' backupFile:'"$bakFile"'"'
				if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
			fi
		        ;;
		n|N )
			echo "no"
			exit 1
			;;
		* )
			echo "invalid!"
			exit 1
			;;
		esac
		break
	done
	echo ''
	echo '#------------------------------------------------'
	$0 ca recover "$sftpAccountName" "$jrNumber"
	echo ''
	echo '#------------------------------------------------'
	$0 home recover "$sftpAccountName" "$jrNumber"
	return 0
}


sendUserCA() {
	# Function implementation to send a certificate to the user

	sftpAccountName="$parameter1"
	sftpUserName="$parameter2"
	sftpUserMail="$parameter3"

	if [ "$sftpAccountName" == "" ]; then
		echo "Usage: $0 ca send <sftp account> [userName] [userMail]"
		exit 1;
	fi

        if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
		echo 'User "'"$sftpAccountName"'" does not exist!'
		exit 1;
	fi

	sftpUserKeysRootDir="$authorizedKeysRootDir"'/'"$sftpAccountName"
	sftpUserKeysDir="$sftpUserKeysRootDir"'/.ssh'
	linuxPathKey="$sftpUserKeysDir"'/'"$sftpAccountName"'_rsa'
	fileZillaPathKey="$sftpUserKeysDir"'/'"$sftpAccountName"'_rsa.ppk'
	fileZillaPathKeyV2="$sftpUserKeysDir"'/'"$sftpAccountName"'_rsa_v2.ppk'
	sftpUserInfo="$sftpUserKeysRootDir"'/'"$sftpUserInfoFileName"

	error=0
	if [ ! -f "$fileZillaPathKey" ]; then
		echo 'Could not find user key file: '"$fileZillaPathKey"
		error=1
	fi
	if [ ! -f "$linuxPathKey" ]; then
		echo 'Could not find user key file: '"$linuxPathKey"
		error=1
	fi
	if [ ! -f "$sftpUserInfo" ]; then
		echo 'Could not find user user info file: '"$sftpUserInfo"
		error=1
	fi
	if [ $error != 0 ]; then
		exit 1
	fi

	sftpUserMail=`cat "$sftpUserInfo" | grep "mail: " | sed 's/mail: //g'`
	if [ "$sftpUserMail" == "" ]; then
		read -p 'Please enter email address of account "'"$sftpAccountName"'": ' mailTo
	else
		mailTo="$sftpUserMail"
	fi
	if ! checkMailRule "$mailTo"; then
		echo 'Email address "'$mailTo'" does not meet the rules!'
		exit 1
	fi

	jrNumber=`cat "$sftpUserInfo" | grep "jr: " | sed 's/jr: //g'`
	if [ "$jrNumber" == "" ]; then
		read -p 'Please enter JR Number of user "'"$sftpAccountName"'": ' var
		jrNumber="`echo $var | tr 'a-z' 'A-Z'`"
	fi
	if ! checkJrRule "$jrNumber"; then
		echo 'JR number "'$jrNumber'" does not meet the rules!'
		exit 1
	fi
	endUserStaffNumber=`cat "$sftpUserInfo" | grep "staff: " | sed 's/staff: //g'`
	userName=`$0 ldap get "$endUserStaffNumber" cn | grep "cn: " | sed 's/cn: //g'`
	if [ "$userName" == "" ]; then
		read -p 'Please enter user name of user "'"$sftpAccountName"'": ' var
		userName="`echo $var | tr 'a-z' 'A-Z'`"
	fi

	echo ''
	echo '#------------------------------------------------'
	echo 'End User Name: '"$userName"
	echo 'End User Mail: '"$mailTo"
	echo 'JR: '"$jrNumber"
	echo 'SFTP Account: '"$sftpAccountName"
	for ((;;)); do
		read -p 'Confirm user information, Continue (y/n)?' choice
		case "$choice" in 
			y|Y )
				echo "yes"
				break
		        	;;
			n|N )
				echo "no"
				exit 1
				;;
			* )
				echo "invalid!"
				;;
		esac
	done
	if [ -f "$fileZillaPathKeyV2" ]; then
		attachmentList="-a $linuxPathKey -a $fileZillaPathKey -a $fileZillaPathKeyV2"
	else
		attachmentList="-a $linuxPathKey -a $fileZillaPathKey"
	fi

	mailSubject='[SFTP Service] SFTP account is ready – ['"$jrNumber"']'
	cat <<-EOF | mail -s "$mailSubject" `echo $attachmentList` -r "$mailFrom" "$mailTo"
	Dear $userName

	The SFTP account has been successfully created with the JR:$jrNumber. Please use the below credentials for SFTP services and keep confidential.

	Username: $sftpAccountName
	Secret key: `echo $sftpAccountName`_rsa.ppk (please download from the attachment)

	Please refer to the detailed User Guide below.

	https://pvtcloud.cmdschool.org/index.php/s/dx7ry7LFaStADDc

	You may contact IT HelpDesk, if you need further assistance or queries. 
	IT Helpdesk: (xx) xxxx

	Note: This email is an automatically generated email from [SFTP Service], please do not respond to this email, and delete immediately after saving the credentials!

	EOF
	if [ "$?" == "0" ]; then
		echo "successfully!"
		changeMsg='sendUserCA "''jr:'"$jrNumber"' account:'"$sftpAccountName"' userTo:'"$userName"' mailTo:'"$mailTo"'"'
		if [[ $logDisable == false ]]; then echo "$nowTime"' '"$changeMsg" >> "$logChange"; fi
	fi
	return 0
}

getLdap() {
	# Function implementation to get user list
	sftpStaffNO="$parameter1"
	sftpStaffAtt="$parameter2"

	ldapAtt='title:|sn:|telexNumber:|telephoneNumber:|cn:|extentionlocation:|mail:|uid:|deptname:|givenName:'
	if [ "$sftpStaffNO" == "" ]; then
		echo "Usage: $0 ldap get <endUser staff No.> [attribute1 attribute2]"
		echo
		echo 'Attribute Values: "'"`echo $ldapAtt | tr -d ':' | tr '|' ' '`"'"'
		exit 1;
	fi

	ldapFilter='(&(|(objectclass=person))(|(uid='$sftpStaffNO')))'

	if [ "$sftpStaffAtt" != "" ]; then
		for i in `echo "$sftpStaffAtt"`; do
			if [ `echo "$ldapAtt" | grep "$i" | wc -l` == "0" ]; then
				echo 'Cannot find attribute "'"$i"'"'
				exit 1
			fi
		done
	fi

	ldapUserInfo="`ldapsearch -x -h "$ldapHost" -p "$ldapPort" -w "$ldapPasswd" -D "$ldapBindDN" -b "$ldapBaseDN" "$ldapFilter" | egrep "$ldapAtt"`"

	if [ "$sftpStaffAtt" != "" ]; then
		for i in `echo "$sftpStaffAtt"`; do
			echo "$ldapUserInfo" | grep "$i"
		done
	else
		echo "$ldapUserInfo"
	fi
}

getLog() {
	sftpAccountName="$parameter1"

	if [ "$sftpAccountName" == "" ]; then
		echo "Usage: $0 log get <sftp account>"
		echo "       $0 log get <all>"
		exit 1;
	fi

	if [ "$sftpAccountName" != "all" ]; then
        	if [ `id "$sftpAccountName" 2>&1 | grep "no such user" | wc -l` == 1 ]; then
			echo 'User "'"$sftpAccountName"'" does not exist!'
			exit 1;
		fi
		ausearch -ue `id -u $sftpAccountName` -i
	fi
	if [ "$sftpAccountName" == "all" ]; then
		ausearch -ge `getent group "$sftpGroupName" | cut -d: -f3` -i
	fi
}

case "$1" in
	user)
		case "$2" in 
			add)
				addUser
				;;
			get)
				getUser
				;;
			del)
				delUser
				;;
			backup)
				bakUser
				;;
			recover)
				recoverUser
				;;
			*)
				echo "Usage: $0 user {add|get|del|backup|recover}"
				;;
		esac
		;;
	passwd)
		case "$2" in 
			reset)
				resetUserPasswd
				;;
			send)
				sendUserPasswd
				;;
			*)
				echo "Usage: $0 passwd {reset|send}"
				;;
		esac
		;;
	home)
		case "$2" in 
			add)
				addUserHome
				;;
			get)
				getUserHome
				;;
			del)
				delUserHome
				;;
			backup)
				bakUserHome
				;;
			recover)
				recoverUserHome
				;;
			*)
				echo "Usage: $0 home {add|get|del|backup|recover}"
				;;
		esac
		;;
	ca)
		case "$2" in 
			add)
				addUserCA
				;;
			get)
				getUserCA
				;;
			del)
				delUserCA
				;;
			reset)
				resetUserCA
				;;
			backup)
				bakUserCA
				;;
			recover)
				recoverUserCA
				;;
			send)
				sendUserCA
				;;
			expire)
				expireUserCA
				;;
			*)
				echo "Usage: $0 ca {add|get|del|reset|backup|recover|send|expire}"
				;;
		esac
		;;
	quota)
		case "$2" in 
			set)
				setQuota
				;;
			get)
				getQuota
				;;
			*)
				echo "Usage: $0 quota {set|get}"
				;;
		esac
		;;
	mount)
		case "$2" in 
			set)
				setMount
				;;
			del)
				delMount
				;;
			get)
				getMount
				;;
			*)
				echo "Usage: $0 mount {set|get|del}"
				;;
		esac
		;;
	ldap)
		case "$2" in 
			get)
				getLdap
				;;
			*)
				echo "Usage: $0 ldap {get}"
				;;
		esac
		;;
	backup)
		case "$2" in 
			get)
				getBackup
				;;
			*)
				echo "Usage: $0 backup {get}"
				;;
		esac
		;;
	log)
		case "$2" in 
			get)
				getLog
				;;
			*)
				echo "Usage: $0 log {get}"
				;;
		esac
		;;
	*)
		echo "Usage: $0 {user|home|ca|passwd|quota|mount|log|ldap|backup}"
    		;;
esac

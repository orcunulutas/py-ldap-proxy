# LDAP PROXY
## Applying manipulations on LDAP

i explained the project in a medium article;
[Medium Post](https://blog.ulu.dev/writing-your-own-ldap-lb-to-manipulate-on-ldap-5e7782fda98)

it will provide solutions to the following issues ;
## Features
- Detecting source ip address over the LB
- Restrict a User to an IP Address
- Virtual password for users
- if there is a machine where the old password has been forgotten, only this ip address is locked instead of the user.
- send logs to logstash

## Structers
- main-ldap-proxy.py - main script
- storepass.py - to read the database file
- tempValue.py - 15 min also for a data deletion (to lock the ip address for bad password attempts)
- hostfilter.py - to filter the ip addresses to which the user will connect
- data Folder
    - settings.conf
    - pass.keyx -  keepass database key file
    - Passwords.kdbx - keepass database file
    - user-host-filter.csv - list of allowed ip addresses of the user


## Package Requirement
```ldaptor
twisted
logstash_async
asyncio
config
json
functools
sys
pi_ldapproxy
threading
uuid
six
re
pykeepass
time
pandas
```

## Settings

Dillinger is currently extended with the following plugins.
Instructions on how to use them in your own application are linked below.

| Conf Header | Settings Value | README |
| ------ | ------ | ------ |
| datafiles | key |  KeePass Database key file |
| datafiles | db |  KeePass Database file |
| datafiles | dbPass |  KeePass Database Password |
| datafiles | dbGroup | in which group to look at users |
| datafiles | cvsData | allowed ip address based user |
| datafiles | csvReloadTime | the number of seconds state that a file will be auto reload. |
| ldapBackend | endpoint | ldap server address with protocol |
| ldapBackend | usetls | ldap server tls usage status |
| logstash | server | logstash server address for send logs to logstash |
| logstash | port | logstash port |


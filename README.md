# opennebula-auth-plugin
Opennebula keycloak auth plugin

## how opennebula works with auth drivers
Authentication drivers are located at /var/lib/one/remotes/auth. There is a directory for each of authentication drivers with an executable inside called authenticate. The name of the directory has to be the same as the user’s auth driver we want to authenticate. For example, if a user has as an auth driver x509 OpenNebula will execute the file /var/lib/one/remotes/auth/x509/authenticate when he performs an OpenNebula action.

Whenever users trying to login to sunstone UI then sunstone will provide a XML format user credentials as an input to the /var/lib/one/remotes/auth/<AUTH_CUSTOM_DRIVER>/authenticate.
```
<AUTHN>
    <USERNAME>VALUE</USERNAME>
    <PASSWORD>VALUE</PASSWORD>
    <SECRET>VALUE</SECRET>
</AUTHN>
```
The password field for external authentication methods typically is "-".
The secret field is the password that user writes in password section of sunstone UI
The username is the username that user writes in the username section of sunstone UI.

if the authenticate script under the /var/lib/one/remotes/auth/<AUTH_CUSTOME_DRIVER>/ return non-status 0 code in the sterr it means the authentication with the specified username and password failed.
If the authentication is successful the authenticate script should return a below format string to output then opennebula understands the the authentication was successful.
```
<AUTH_CUSTOM_DRIVER> username secret
exp: ldap username1 username1passxx
exp: keycloak username1 passw1
```



## Using the keycloak custom auth provider

1. Build the keycloak custom auth provider on opennebula server
```
$ sudo -u oneadmin mkdir -p /var/lib/one/remotes/auth/keycloak/
$ chmod -R 750 /var/lib/one/remotes/auth/keycloak/
$ sudo add-apt-repository ppa:longsleep/golang-backports
$ sudo apt update
$ sudo apt install golang-go
$ env GOOS=linux GOARCH=amd64 go build -o /var/lib/one/remotes/auth/keycloak/authenticate main.go
```

2. Configure keycloak endpoint on /etc/one/auth/keycloak_auth.conf
```
$ vim /etc/one/auth/keycloak_auth.conf

## server_addr: address of keycloak server
## server_port: port of the keycloak server
## server_trustbundle_crt: list of trusted_ca_certificate bundle of keycloak server in pem format 
## config_endpoint: keycloak configuration endpoint address ..../.well-known/openid-configuration. Can be different on different keycloak versions.
## client_id: created in keycloak 
## client_secret: "secret of the client"
## grant_type: which should be always password


keycloak:
  server_addr: "SNAPP_KEYCLOAK_SERVER_ADDRESS"
  server_port: 443
  server_trustbundle_crt:
  - /etc/ssl/snapp-keycloak.pem
  config_endpoint: /realms/<REALM_NAME>/.well-known/openid-configuration
  client:
    client_id: "opennebula"
    client_secret: "kljslkajdoqiooqwe"
    grant_type: password

```

3. Configure opennebula to have this auth plugin as the default plugin
```
$ vim /etc/one/oned.conf 

AUTH_MAD = [
    EXECUTABLE = "one_auth_mad",
    AUTHN = "keycloak,ssh,x509,ldap,server_cipher,server_x509"
]

DEFAULT_AUTH = "keycloak"

AUTH_MAD_CONF = [
    NAME = "keycloak",
    PASSWORD_CHANGE = "YES",
    DRIVER_MANAGED_GROUPS = "YES",
    DRIVER_MANAGED_GROUP_ADMIN = "NO",
    MAX_TOKEN_TIME = "-1"
]

$ systemctl restart opennebula.service
```
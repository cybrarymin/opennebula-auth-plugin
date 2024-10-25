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

1. Build the keycloak custom auth provider
```
$ mkdir -p /var/lib/one/remotes/auth/keycloak/
env GOOS=linux GOARCH=amd64 go build -o /var/lib/one main.go
```

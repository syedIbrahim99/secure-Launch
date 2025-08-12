Secured Docker Runtime:
=======================

securing test user's path from root:  
===================================

--> create user named "eminds"

--> Give "sudo" access for this user "eminds"

contents inside "rootless-docker-script" binary:
===============================================

wget https://download.docker.com/linux/static/stable/x86_64/docker-28.3.2.tgz 
wget https://download.docker.com/linux/static/stable/x86_64/docker-rootless-extras-28.3.2.tgz
tar -xvf docker-28.3.2.tgz
tar -xvf docker-rootless-extras-28.3.2.tgz
sudo apt update
sudo apt install -y uidmap dbus-user-session
mkdir -p $HOME/.execute/custom
mkdir -p $HOME/.execute/custom/bin
export PATH=$HOME/.execute/custom/bin:$PATH
cp docker/*  $HOME/.execute/custom/bin
cp docker-rootless-extras/*  $HOME/.execute/custom/bin
dockerd-rootless-setuptool.sh install

eminds user:
===========

mkdir -p $HOME/.execute/custom

nano /home/eminds/.execute/custom rootless-docker-setup.sh

chmod 700 rootless-docker-setup.sh

--> Paste the "rootless docker" installation steps here which is above given.

sudo apt update

sudo apt install shc -y

sudo apt install build-essential -y

shc -f rootless-docker-setup.sh -o rootless-docker-setup

Note: 

--> This "rootless-docker-setup" file will work only if it is compiled on Ubuntu or a similar OS. 
--> If we try to run it on Alpine, it won’t work because Alpine uses different system libraries.

Before Installing Rootless Docker:
=================================

export PATH=$HOME/.execute/custom/bin:$PATH

------------------------------------------------------------------------------------------------------------------------------------------------------------

./rootless-docker-setup

systemctl --user start docker

systemctl --user enable docker

systemctl --user status docker

--> "docker ps" working

sudo loginctl enable-linger eminds

Reason for Linger in Rootless Docker:
====================================

* Rootful Docker runs as root with a system-wide service (/etc/systemd/system/docker.service) and starts automatically at boot.

* Rootless Docker runs under a normal user (eminds) and is tied to the user’s login session. Without linger:

  - Services stop when user logs out.

  - Services don’t start after reboot until the user logs in.

* loginctl enable-linger eminds keeps user services running even when logged out.

Con script:
==========

sudo nano /home/eminds/.execute/custom/bin/script.sh

-----------------------------------

CON=$HOME/.execute/custom
export DOCKER_HOST=unix:///$XDG_RUNTIME_DIR/docker.sock
con() {
  # Hardcoded credentials (you can externalize this later)
  local VALID_USER="devops"
  local VALID_PASS="Eminds@1"

  # Prompt for username
  echo -n "Username: "
  read USERNAME

  # Prompt for password silently
  echo -n "Password: "
  read -s PASSWORD
  echo

  # Validate credentials
  if [[ "$USERNAME" != "$VALID_USER" || "$PASSWORD" != "$VALID_PASS" ]]; then
    echo "Authentication failed!"
    return 1
  fi

  # Auth success — proceed
  if [[ "$1" == "ps" ]]; then
    "$CON"/bin/docker ps -a
  elif [[ "$1" == "inspect" ]]; then
    "$CON"/bin/docker "$@" | jq '.[0] | {Name: .Name, Status: .State.Status}'
  elif [[ "$1" == "run" ]]; then
    "$CON"/bin/docker "$@"
  else
    echo "Unauthorized! Please Contact DevOps."
  fi
}

------------------------------------------------------------------------------------------------------------------------------------------------------------

sudo chmod 700 script.sh

sudo chown eminds:eminds script.sh



Restricting "su" user:
=====================

--> Perform this all from "eminds" user.

sudo groupadd suaccess

sudo chown eminds:suaccess /bin/su

sudo chown eminds:suaccess /usr/bin/su

sudo chmod 4750 /bin/su

sudo chmod 4750 /usr/bin/su

Explanation:
===========

4 = setuid (required for su to work)

7 = full access to owner (root)

5 = read + execute for group (suaccess)

0 = no access to others

------------------------------------------------------------------------------------------------------------------------------------------------------------

ls -l /bin/su /usr/bin/su

sudo usermod -aG suaccess eminds

--> Log out and log back in

su

--> If other users run su, they get "Permission denied" because they are not in the suaccess group.

--> If they run "sudo su", it will still fail — sudo tries to run /bin/su, but since the file is owned by "eminds" instead of "root", it cannot run with the required root privileges, so it cannot switch users.

--> When "eminds" runs su, it will ask for the root password.

--> Even if the correct password is entered, it will show "Authentication failure", because changing the file owner from root to eminds removes the root privilege from the setuid bit. Without root privileges, su cannot read /etc/shadow to verify passwords.

--> As a result, even "eminds" cannot switch to root unless the ownership of /bin/su and /usr/bin/su is changed back to "root".



How to change "su" password:
===========================

--> login as root

passwd

--> Enter new password
--> retype new password

Making the "su" ask password when used from "root"
=================================================

sudo nano /etc/pam.d/su

auth       sufficient pam_rootok.so  (comment this line)

auth       required pam_wheel.so     (uncomment this line)

sudo usermod -aG sudo eminds

--> so now if we run "su test" from root, it will prompt for password.


sudo chmod 700 *

chmod 700 custom

--> run this command in all paths of "eminds" user, so that other users will not have a permission to view these directories, apart from root.



After Login:
===========

export CON_BIN=$HOME/.execute/custom/bin
source $HOME/.execute/custom/bin/script.sh

con ps

username: devops
password: Eminds@1

------------------------------------------------------------------------------------------------------------------------------------------------------------

Adding MFA to a ubuntu machine user:
===================================

users in the machine:
=====================

* test 
* eminds

---------------------------------------------------------------------------------------------------------------------------------------------------------

steps:
=====

sudo apt update -y

sudo apt install libpam-google-authenticator -y

---------------------------------------------------------------------------------------------------------------------------------------------------------

--> login to "eminds" user

google-authenticator

--> scan the QR, then give "Y" for all.

--> after running this command, it will create a ".google_authenticator" file in the "home" path of the "eminds" user.

--> If we want MFA for other users, have to run this "google-authenticator" command in that user and scan the QR.

---------------------------------------------------------------------------------------------------------------------------------------------------------

sudo nano /etc/pam.d/sshd

--> Add these lines after "@include common-auth"

auth [success=1 default=ignore] pam_succeed_if.so user != eminds
auth required pam_google_authenticator.so 

--> the first line checks whether the user is not "eminds". so if the user is not "eminds" and it become true and skips the next line

--> suppose if the user is "eminds", the condition will be satisfied and it will fail and run the next line, this next line will expect MFA OTP from that logging user.

---------------------------------------------------------------------------------------------------------------------------------------------------------

sudo nano /etc/ssh/sshd_config

ChallengeResponseAuthentication yes
UsePAM yes
PasswordAuthentication yes

---------------------------------------------------------------------------------------------------------------------------------------------------------

sudo systemctl restart ssh

---------------------------------------------------------------------------------------------------------------------------------------------------------

--> Now if we try to login as "eminds" , prompt for "password" and "verification code"
--> Now if we try to login as "test" , prompt for "password" and skips MFA, because "/etc/pam.d/sshd" in this path, we added a login , that if it is a "eminds" user, checks for MFA and skips MFA for other users. 

sudo tail -f /var/log/auth.log

--> To see logs

---------------------------------------------------------------------------------------------------------------------------------------------------------

cat .google_authenticator

FHMTK5JAHCR2EIJYQZ26RJI5CY
" RATE_LIMIT 3 30 1753775161
" WINDOW_SIZE 17
" DISALLOW_REUSE 58459158 58459172
" TOTP_AUTH
92241159
20376124
73657003
37324602
80611254



Secure Launch: (Secured Deployment strategies)
===============

Layers of security:
==================

* Host machine
* Host & Docker Network Security
* Runtime environment 
* Docker container
* Docker Image
* Application (Binary)


Docker Image Security Steps:
===========================

Image Description:
=================

* To minimize the image size we have chosen Alpine image(~8.31MB).
* For Nodejs(20,18) as runtime built on Alpine image, the size ranges from ~(120MB-140MB).
* For Python(3.11,3.9) as runtime built on Alpine image, the size ranges from ~(45MB-60MB).
* For OpenJDK(17,18,19) as runtime built on Alpine image, the size ranges from ~(320MB-350MB).

Security Highlights:
===================


  Image and Container Security:
  ----------------------------

    * All available SHELL and user bin modules from the base images are removed, ensuring high level container entry restriction.
    * Shell(/bin/sh) is overwritten by our custom entry script.
    * This entry-script is composed of users(root, eminds) and terminal mode based privileges and restrictions.
    * On an instance, running a container image or exec into a container or running a process inside a running container are constrained by the above mentioned entry script.

  Hardened Dockerfile: [Nodejs 20] [alpine:18.5.0-alpine hardened]
  --------------------
 
FROM alpine:18.5.0-alpine


#Install required packages
RUN apk update && apk add --no-cache     sudo     shadow     && rm -rf /var/cache/apk/*

WORKDIR /app

#Create app.sh script
RUN printf '#!/execute/.custom/bin/sh\nwhile true; do\n  echo "Application running..."\n  sleep 1\ndone' > app.sh && chmod +x app.sh

#Create user 'eminds' with password '12345'
RUN adduser -D -h /home/eminds -s /bin/sh eminds  && echo "eminds:12345" | chpasswd  && addgroup eminds wheel  && echo "%wheel ALL=(ALL) ALL" >> /etc/sudoers

#Set /app directory ownership
RUN chmod 750 /app && chown eminds:eminds /app
RUN chmod 750 /app/* && chown eminds:eminds /app/*

#Create custom bash paths
RUN mkdir -p /execute/.custom/entry  && mkdir -p /execute/.custom/bin  && mkdir -p /execute/.custom/usr/bin

#Create secure interactive shell wrapper
RUN printf '#!/execute/.custom/bin/sh\nREAL_SHELL="/execute/.custom/bin/sh"\nif [ "$(whoami)" != "eminds" ] && [ "$(whoami)" != "root" ]; then\n  echo "Access denied: only admin is allowed"\n  exit 1\nfi\nif [ -t 0 ] && [ -t 1 ] && [ "$(whoami)" = "eminds" ] && [ "$(whoami)" != "root" ]; then\n  echo -n "Password: "\n  read -s input_pass\n  echo\n  if [ "$input_pass" = "Eminds@10540" ]; then\n    echo "Access granted"\n    exec "$REAL_SHELL" "$@"\n  else\n    echo "Incorrect password"\n    exit 1\n  fi\nelif [ "$(whoami)" = "eminds" ]; then\n  exec "$REAL_SHELL" "$@"\n  exit 1\nelse\n  echo "Access denied for root in non-interactive shell."\n  exit 1\nfi' > /execute/.custom/entry/sash && chmod +x /execute/.custom/entry/sash

#Copy binaries to custom dir
RUN cp -a /bin/* /execute/.custom/bin/ || true && chmod +x /execute/.custom/bin/* || true
RUN cp -a /usr/bin/* /execute/.custom/usr/bin/ || true && chmod +x /execute/.custom/usr/bin/* || true

#Set correct permissions
RUN chmod +x /execute/.custom/bin/sh && chown eminds:eminds /execute/.custom/bin/sh

RUN mkdir /public && chown -R eminds:eminds /public
RUN chown -R eminds:eminds /home/eminds/
#RUN chmod +x /usr/local/bin/npm && chown -R eminds:eminds /usr/local/bin/npm

#Lock root account
RUN passwd -l root  && usermod -s /sbin/nologin root  && usermod -L root  && chmod 750 /execute/.custom/bin/sh

#Set PATH (PIP path required by the SHELL for Python Modules after Pyinstaller)
ENV PATH="/home/eminds/.local/bin:/execute/.custom/entry:$PATH"

#Remove sensitive/default shells and tools (as in original)
RUN rm -f # /bin/sh /usr/bin/sh  /bin/bash /usr/bin/bash /usr/local/bin/bash  /usr/bin/cat /bin/cat /bin/ls /usr/bin/ls  /usr/bin/less /usr/bin/more /usr/bin/view /usr/bin/nano /usr/bin/vim  /usr/bin/file /usr/bin/tree /usr/bin/awk /usr/bin/stat  /usr/bin/head /usr/bin/tail /usr/bin/watch /bin/watch

#Replace /bin/sh with custom sash:
RUN cp /execute/.custom/entry/sash /bin/sh && chmod +x /bin/sh


#docker build -t emindsguardians/alpine:latest-hard .

  
Dockerfile: (Hardened image with /home/eminds)
==========

FROM node:18.5.0-alpine AS codeshelf

WORKDIR /home/eminds/app

ADD source-code /home/eminds/app
RUN chown -R 1001:1001 /home/eminds/app
RUN npm install --force
RUN npx tsc
RUN npm install -g pkg
RUN pkg . --targets node18-alpine-x64 --output app-binary
RUN chmod +x app-binary && chown -R 1001:1001 app-binary

FROM  emindsguardians/alpine:latest-hard

WORKDIR /home/eminds
COPY --from=codeshelf /home/eminds/app/app-binary /home/eminds
COPY --from=codeshelf /home/eminds/app/.env /home/eminds/.env
#CMD [./app-binary]

#docker build -t emindsguardians/service:alpine-hard-gateway .

## Node: Tag (privaterepo.com:5000/node:18.5.0-alpine-hard)

```bash
#FROM runtime:version-os
FROM node:18.5.0-alpine
#Install required packages
#Install required packages
RUN apk update && apk add --no-cache \
    sudo \
    shadow \
    && rm -rf /var/cache/apk/*
WORKDIR /app
#Create app.sh script
RUN printf '#!/execute/.custom/bin/sh\n\
while true; do\n\
  echo "Application running..."\n\
  sleep 1\n\
done' > app.sh && chmod +x app.sh
#Create user 'eminds' with password '12345'
RUN adduser -D -h /home/eminds -s /bin/sh -u 1001 eminds \
&& echo "eminds:12345" | chpasswd \
&& addgroup eminds wheel \
&& echo "%wheel ALL=(ALL) ALL" >> /etc/sudoers
#Set /app directory ownership
RUN chmod 750 /app && chown eminds:eminds /app
RUN chmod 750 /app/* && chown eminds:eminds /app/*
#Create custom bash paths
RUN mkdir -p /execute/.custom/entry \
&& mkdir -p /execute/.custom/bin \
&& mkdir -p /execute/.custom/usr/bin
#Create secure interactive shell wrapper
RUN printf '#!/execute/.custom/bin/sh\n\
REAL_SHELL="/execute/.custom/bin/sh"\n\
if [ "$(whoami)" != "eminds" ] && [ "$(whoami)" != "root" ]; then\n\
  echo "Access denied: only admin is allowed"\n\
  exit 1\n\
fi\n\
if [ -t 0 ] && [ -t 1 ] && [ "$(whoami)" = "eminds" ] && [ "$(whoami)" != "root" ]; then\n\
  echo -n "Password: "\n\
  read -s input_pass\n\
  echo\n\
  if [ "$input_pass" = "Eminds@10540" ]; then\n\
    echo "Access granted"\n\
    exec "$REAL_SHELL" "$@"\n\
  else\n\
    echo "Incorrect password"\n\
    exit 1\n\
  fi\n\
elif [ "$(whoami)" = "eminds" ]; then\n\
  exec "$REAL_SHELL" "$@"\n\
  exit 1\n\
else\n\
  echo "Access denied for root in non-interactive shell."\n\
  exit 1\n\
fi' > /execute/.custom/entry/sash && chmod +x /execute/.custom/entry/sash
#Copy binaries to custom dir
RUN cp -a /bin/* /execute/.custom/bin/ || true && chmod +x /execute/.custom/bin/* || true
RUN cp -a /usr/bin/* /execute/.custom/usr/bin/ || true && chmod +x /execute/.custom/usr/bin/* || true
#Set correct permissions
RUN chmod +x /execute/.custom/bin/sh && chown eminds:eminds /execute/.custom/bin/sh
RUN mkdir /public && chown -R eminds:eminds /public
RUN chown -R eminds:eminds /home/eminds/
#RUN chmod +x /usr/local/bin/npm && chown -R eminds:eminds
#/usr/local/bin/npm
#Lock root account
RUN passwd -l root \
&& usermod -s /sbin/nologin root \
&& usermod -L root \
&& chmod 750 /execute/.custom/bin/sh
#Set PATH (PIP path required by the SHELL for Python Modules after Pyinstaller)
ENV PATH="/home/eminds/.local/bin:/execute/.custom/entry:$PATH"
#Remove sensitive/default shells and tools (as in original)
RUN rm -f \
#/bin/sh /usr/bin/sh \
/bin/bash /usr/bin/bash /usr/local/bin/bash \
/usr/bin/cat /bin/cat /bin/ls /usr/bin/ls \
/usr/bin/less /usr/bin/more /usr/bin/view /usr/bin/nano /usr/bin/vim \
/usr/bin/file /usr/bin/tree /usr/bin/awk /usr/bin/stat \
/usr/bin/head /usr/bin/tail /usr/bin/watch /bin/watch
#Replace /bin/sh with custom sash:
RUN cp /execute/.custom/entry/sash /bin/sh && chmod +x /bin/sh
#docker build -t emindsguardians/alpine:latest-hard .

```

## Python: Tag (privaterepo.com:5000/base:python3.11-alpine-hard)

```bash
FROM python:3.11-alpine
#Install required packages
#Install required packages
RUN apk update && apk add --no-cache \
    sudo \
    shadow \
    && rm -rf /var/cache/apk/*
WORKDIR /app
#Create app.sh script
RUN printf '#!/execute/.custom/bin/sh\n\
while true; do\n\
  echo "Application running..."\n\
  sleep 1\n\
done' > app.sh && chmod +x app.sh
#Create user 'eminds' with password '12345'
RUN adduser -D -h /home/eminds -s /bin/sh eminds \
 && echo "eminds:12345" | chpasswd \
 && addgroup eminds wheel \
 && echo "%wheel ALL=(ALL) ALL" >> /etc/sudoers
#Set /app directory ownership
RUN chmod 750 /app && chown eminds:eminds /app
RUN chmod 750 /app/* && chown eminds:eminds /app/*
#Create custom bash paths
RUN mkdir -p /execute/.custom/entry \
 && mkdir -p /execute/.custom/bin \
 && mkdir -p /execute/.custom/usr/bin
#Create secure interactive shell wrapper
RUN printf '#!/execute/.custom/bin/sh\n\
REAL_SHELL="/execute/.custom/bin/sh"\n\
if [ "$(whoami)" != "eminds" ] && [ "$(whoami)" != "root" ]; then\n\
  echo "Access denied: only admin is allowed"\n\
  exit 1\n\
fi\n\
if [ -t 0 ] && [ -t 1 ] && [ "$(whoami)" = "eminds" ] && [ "$(whoami)" != "root" ]; then\n\
  echo -n "Password: "\n\
  read -s input_pass\n\
  echo\n\
  if [ "$input_pass" = "Eminds@10540" ]; then\n\
    echo "Access granted"\n\
    exec "$REAL_SHELL" "$@"\n\
  else\n\
    echo "Incorrect password"\n\
    exit 1\n\
  fi\n\
elif [ "$(whoami)" = "eminds" ]; then\n\
  exec "$REAL_SHELL" "$@"\n\
  exit 1\n\
else\n\
  echo "Access denied for root in non-interactive shell."\n\
  exit 1\n\
fi' > /execute/.custom/entry/sash && chmod +x /execute/.custom/entry/sash
#Copy binaries to custom dir
RUN cp -a /bin/* /execute/.custom/bin/ || true && chmod +x /execute/.custom/bin/* || true
RUN cp -a /usr/bin/* /execute/.custom/usr/bin/ || true && chmod +x /execute/.custom/usr/bin/* || true
#Set correct permissions
RUN chmod +x /execute/.custom/bin/sh && chown eminds:eminds /execute/.custom/bin/sh
RUN mkdir /public && chown -R eminds:eminds /public
RUN chown -R eminds:eminds /home/eminds/
#RUN chmod +x /usr/local/bin/npm && chown -R eminds:eminds
#/usr/local/bin/npm
#Lock root account
RUN passwd -l root \
 && usermod -s /sbin/nologin root \
 && usermod -L root \
 && chmod 750 /execute/.custom/bin/sh
#Set PATH (PIP path required by the SHELL for Python Modules after Pyinstaller)
ENV PATH="/home/eminds/.local/bin:/execute/.custom/entry:$PATH"
#Remove sensitive/default shells and tools (as in original)
RUN rm -f \
#/bin/sh /usr/bin/sh \
 /bin/bash /usr/bin/bash /usr/local/bin/bash \
 /usr/bin/cat /bin/cat /bin/ls /usr/bin/ls \
 /usr/bin/less /usr/bin/more /usr/bin/view /usr/bin/nano /usr/bin/vim \
 /usr/bin/file /usr/bin/tree /usr/bin/awk /usr/bin/stat \
 /usr/bin/head /usr/bin/tail /usr/bin/watch /bin/watch
#Replace /bin/sh with custom sash:
RUN cp /execute/.custom/entry/sash /bin/sh && chmod +x /bin/sh

```

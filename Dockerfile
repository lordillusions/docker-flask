FROM ubuntu:latest
MAINTAINER Wellington Chaves "wchaves@gmail.com"
RUN apt-get update -y
RUN apt-get install -y python-pip python-dev build-essential libxmlsec1-dev libtiff5-dev libjpeg8-dev zlib1g-dev libfreetype6-dev openssl
RUN mkdir -p /opt/app/
COPY app /opt/app
WORKDIR /opt/app/saml/certs/
RUN openssl genrsa -des3 -passout pass:x -out sp.pass.key 2048
RUN openssl rsa -passin pass:x -in sp.pass.key -out sp.key
RUN rm sp.pass.key
RUN openssl req -new -key sp.key -out sp.csr -subj "/C=BR/ST=SP/L=Sao Paulo/O=IBM/OU=GBS/CN=mybluemix.net"
RUN openssl x509 -req -days 365 -in sp.csr -signkey sp.key -out sp.crt
RUN chmod 644 sp.*
WORKDIR /opt/app/
RUN pip install -r requirements.txt
ENTRYPOINT ["python"]
CMD ["welcome.py"]
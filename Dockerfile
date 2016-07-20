FROM ubuntu:latest
MAINTAINER Wellington Chaves "wchaves@gmail.com"
RUN apt-get update -y
RUN apt-get install -y python-pip python-dev build-essential libxmlsec1-dev libtiff5-dev libjpeg8-dev zlib1g-dev libfreetype6-dev openssl
RUN mkdir -p /app
COPY . /app
WORKDIR /app
RUN openssl genrsa -des3 -passout pass:x -out /saml/certs/sp.pass.key 2048
RUN openssl rsa -passin pass:x -in /saml/certs/sp.pass.key -out /saml/certs/sp.key
RUN openssl req -new -key /saml/certs/sp.key -out /saml/certs/sp.csr -subj "/C=BR/ST=SP/L=Sao Paulo/O=IBM/OU=GBS/CN=mybluemix.net"
RUN openssl x509 -req -days 365 -in /saml/certs/sp.csr -signkey /saml/certs/sp.key -out /saml/certs/sp.crt
RUN rm /saml/certs/sp.pass.key
RUN pip install -r requirements.txt
EXPOSE 80
ENTRYPOINT ["python"]
CMD ["welcome.py"]
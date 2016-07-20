FROM ubuntu:latest
MAINTAINER Wellington Chaves "wchaves@gmail.com"
RUN apt-get update -y
RUN apt-get install -y python-pip python-dev build-essential libxmlsec1-dev libtiff5-dev libjpeg8-dev zlib1g-dev libfreetype6-dev openssl
RUN mkdir -p /app
COPY . /app
WORKDIR /app
RUN openssl req -new -key /opt/app/saml/certs/sp.key -out /opt/app/saml/certs/sp.csr -subj "/C=BR/ST=SP/L=Sao Paulo/O=IBM/OU=GBS/CN=mybluemix.net"
RUN openssl x509 -req -days 365 -in /opt/app/saml/certs/sp.csr -signkey /opt/app/saml/certs/sp.key -out /opt/app/saml/certs/sp.crt
RUN pip install -r requirements.txt
EXPOSE 80
ENTRYPOINT ["python"]
CMD ["welcome.py"]
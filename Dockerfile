FROM ubuntu:latest
MAINTAINER Wellington Chaves "wchaves@gmail.com"
RUN apt-get update -y
RUN apt-get install -y python-pip python-dev build-essential libxmlsec1-dev libtiff5-dev libjpeg8-dev zlib1g-dev libfreetype6-dev openssl
RUN mkdir -p /opt/app/
COPY app /opt/app
WORKDIR /opt/app
RUN openssl req -x509 -subj "/C=BR/ST=SP/L=SaoPaulo/O=Dis/CN=travelibm.mybluemix.net" -nodes -days 365 -newkey rsa:2048 -keyout /opt/app/saml/certs/sp.key -out /opt/app/saml/certs/sp.crt 
#RUN openssl genrsa -des3 -out /opt/app/saml/certs/sp.key.protected 2048
#RUN openssl req -new -key /opt/app/saml/certs/sp.key.protected -out /opt/app/saml/certs/sp.csr
#RUN openssl rsa -in /opt/app/saml/certs/sp.key.protected -out /opt/app/saml/certs/sp.key
#RUN openssl x509 -req -days 365 -in /opt/app/saml/certs/sp.csr -signkey /opt/app/saml/certs/sp.key -out /opt/app/saml/certs/sp.crt
RUN chmod 644 /opt/app/saml/certs/sp.*
RUN pip install -r requirements.txt
ENTRYPOINT ["python"]
CMD ["welcome.py"]
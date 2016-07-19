FROM ubuntu:latest
MAINTAINER Wellington Chaves "wchaves@gmail.com"
RUN apt-get update -y
RUN apt-get install -y python-pip python-dev build-essential libxmlsec1-dev libtiff5-dev libjpeg8-dev zlib1g-dev libfreetype6-dev
RUN mkdir -p /opt/app/
COPY app /opt/app
WORKDIR /opt/app
RUN pip install -r requirements.txt
ENTRYPOINT ["python"]
CMD ["welcome.py"]
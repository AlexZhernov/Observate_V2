FROM tiangolo/uwsgi-nginx-flask:python3.7

RUN apt-get update && apt-get install -y nmap

COPY ./app /app

RUN pip install -r /app/requirements.txt




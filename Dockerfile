FROM tiangolo/uvicorn-gunicorn-fastapi:python3.7
RUN apt-get update -y && \
    apt-get install -y libsasl2-dev python-dev libldap2-dev libssl-dev libsnmp-dev
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY ./app /app

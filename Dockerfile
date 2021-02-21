FROM python:3-slim
COPY ./app /app
WORKDIR /app

RUN apt-get update && apt-get install -y curl
RUN curl -sSL https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN python get-pip.py

COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt
EXPOSE 8080

CMD [ "python", "main.py" ]

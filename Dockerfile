FROM python:3.8.0a3-slim
COPY ./app /app
WORKDIR /app

RUN apt-get update && apt-get install -y curl gcc g++ libffi-dev
RUN curl -sSL https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN python get-pip.py

COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]


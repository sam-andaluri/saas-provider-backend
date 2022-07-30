FROM python:3-slim
COPY ./src/ /src
WORKDIR /src/app

RUN apt-get update && apt-get install -y curl gcc g++ libffi-dev
RUN curl -sSL https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN python get-pip.py

COPY ./src/requirements.txt /src/app/requirements.txt
RUN pip install -r /src/app/requirements.txt

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]

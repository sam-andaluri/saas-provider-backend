FROM python:3-slim AS build-env
COPY ./app /app
WORKDIR /app

FROM gcr.io/distroless/python3
COPY --from=build-env /app /app
WORKDIR /app

RUN set -xe \
    && apt-get update \
    && apt-get install python-pip

COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt
EXPOSE 8080

CMD [ "python", "main.py" ]

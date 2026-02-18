ARG BUILD_FROM=python:3.12-alpine
FROM ${BUILD_FROM}

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY run.sh /run.sh

RUN chmod a+x /run.sh

CMD [ "/run.sh" ]

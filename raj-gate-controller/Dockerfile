ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN apk add --no-cache python3 py3-pip

RUN pip3 install --no-cache-dir --upgrade pip

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY run.sh /

RUN chmod a+x /run.sh

CMD [ "/run.sh" ]

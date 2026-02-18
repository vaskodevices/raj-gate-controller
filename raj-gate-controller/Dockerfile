ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN apk add --no-cache python3 py3-pip bash

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY run.sh /

RUN chmod a+x /run.sh

# Support both s6-overlay v2 and v3
RUN mkdir -p /etc/services.d/raj-gate-controller && \
    cp /run.sh /etc/services.d/raj-gate-controller/run && \
    chmod a+x /etc/services.d/raj-gate-controller/run

# s6-overlay v3 style
RUN mkdir -p /etc/s6-overlay/s6-rc.d/raj-gate-controller && \
    echo "longrun" > /etc/s6-overlay/s6-rc.d/raj-gate-controller/type && \
    cp /run.sh /etc/s6-overlay/s6-rc.d/raj-gate-controller/run && \
    chmod a+x /etc/s6-overlay/s6-rc.d/raj-gate-controller/run && \
    mkdir -p /etc/s6-overlay/s6-rc.d/user/contents.d && \
    touch /etc/s6-overlay/s6-rc.d/user/contents.d/raj-gate-controller

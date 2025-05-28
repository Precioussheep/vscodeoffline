FROM python:3.13-alpine AS build

RUN apk --no-cache add libc-dev binutils 

WORKDIR /opt/build

# create & install vscoffline package to then provide to second image
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY . .

RUN python3 -m pip install --no-cache-dir --upgrade pip wheel setuptools && \
    python3 -m pip install --no-cache-dir --compile .[server]

FROM python:3.13-alpine AS deploy

RUN apk --no-cache upgrade && \
    apk --no-cache add libc-dev binutils && \
    mkdir /artifacts/

COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    ARTIFACTS=/artifacts \
    HOST=0.0.0.0 \
    PORT=9000 \
    TIMEOUT=180

COPY ./vscoffline/vscgallery /app/vscgallery
COPY ./vscoffline/server.py /app/server.py

ADD https://cdn.jsdelivr.net/npm/swagger-ui-dist@4/swagger-ui-bundle.js /static/swagger-ui-bundle.js
ADD https://cdn.jsdelivr.net/npm/swagger-ui-dist@4/swagger-ui.css /static/swagger-ui.css
ADD https://fastapi.tiangolo.com/img/favicon.png /static/favicon.png
ADD https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js /static/redoc.standalone.js

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=2 \
    CMD wget -O - http://$HOST:$PORT || exit 1

WORKDIR /app
SHELL [ "/bin/sh", "-c" ]
CMD uvicorn --host $HOST \
    --port $PORT \
    --timeout-keep-alive $TIMEOUT \
    server:app

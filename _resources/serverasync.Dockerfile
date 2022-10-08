FROM python:3.10-alpine as build

RUN apk --no-cache add libc-dev binutils 

WORKDIR /opt/build

# create & install vscoffline package to then provide to second image
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY . .

RUN python3 -m pip install --no-cache-dir --upgrade pip wheel setuptools && \
    python3 -m pip install --no-cache-dir --compile .[server_async]

FROM python:3.10-alpine as deploy

RUN apk --no-cache upgrade && \
    apk --no-cache add libc-dev binutils && \
    mkdir /artifacts/

COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    ARTIFACTS=/artifacts \
    HOST=0.0.0.0 \
    PORT=9000 \
    TIMEOUT=180

WORKDIR /app

COPY ./vscoffline/vscgallery /opt/vscoffline/vscgallery
COPY ./vscoffline/server_async.py /app/server_async.py

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=2 \
    CMD curl -f -k http://$HOST:$PORT || exit 1

CMD uvicorn --host ${HOST} \ 
    --port ${PORT} \
    --timeout-keep-alive ${TIMEOUT} \
    server_async:app

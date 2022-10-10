FROM python:3.10-alpine as build

# For: gunicorn > 20.0.0, falcon to cythonize itself, gevent to build
RUN apk --no-cache add build-base 

WORKDIR /opt/build

# create & install vscoffline package to then provide to second image
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY . .

RUN python3 -m pip install --no-cache-dir --upgrade pip wheel setuptools cython && \
    python3 -m pip install --no-cache-dir .[server]

FROM python:3.10-alpine as deploy

RUN apk --no-cache upgrade && \
    mkdir /artifacts/

COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    ARTIFACTS=/artifacts \
    BIND=0.0.0.0:9000 \
    TIMEOUT=180 \
    WORKERS=2 \
    THREADS=8 \
    WORKER_CLS="gevent"

WORKDIR /app

COPY ./vscoffline/vscgallery /opt/vscoffline/vscgallery
COPY ./vscoffline/server.py /app/server.py

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=2 \
    CMD curl -f -k http://$BIND || exit 1
CMD gunicorn --bind $BIND \
    --access-logfile - --timeout $TIMEOUT \
    --threads $THREADS \
    --workers $WORKERS \
    --worker-class $WORKER_CLS \
    server:application

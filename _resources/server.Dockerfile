FROM python:3.10-alpine as build

# For gunicorn > 20.0.0
RUN apk --no-cache add libc-dev binutils 

WORKDIR /opt/build

# create & install vscoffline package to then provide to second image
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY . .

RUN pip3 install --no-cache-dir --upgrade pip wheel setuptools && \
    pip3 install --no-cache-dir .[server]

FROM python:3.10-alpine as deploy

# For gunicorn > 20.0.0
RUN apk --no-cache upgrade && \
    apk --no-cache add libc-dev binutils 

COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    ARTIFACTS=/artifacts \
    BIND=0.0.0.0:443 \
    TIMEOUT=180 \
    THREADS=4 

RUN mkdir /artifacts/

WORKDIR /app

COPY ./vscoffline/vscgallery /opt/vscoffline/vscgallery
COPY ./vscoffline/server.py /app/server.py

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=2 \
    CMD curl -f -k https://localhost:443/ || exit 1
CMD gunicorn --bind $BIND \
    --certfile=/opt/vscoffline/vscgallery/ssl/vscoffline.crt --keyfile=/opt//vscoffline/vscgallery/ssl/vscoffline.key \
    --access-logfile - --reload --timeout $TIMEOUT --threads $THREADS \
    server:application

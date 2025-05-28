FROM python:3.13-alpine AS build

WORKDIR /opt/build

# create & install vscoffline package to then provide to second image
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY . .

RUN python3 -m pip install --no-cache-dir --upgrade pip wheel setuptools && \
    python3 -m pip install --no-cache-dir --compile .

FROM python:3.13-alpine AS deploy

# upgrade image &
# setup default artifacts location
RUN apk upgrade --no-cache && \
    mkdir /artifacts

COPY --from=build /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    ARTIFACTS=/artifacts \
    SYNCARGS=--sync

COPY ./vscoffline/sync.py /app/sync.py

WORKDIR /app
SHELL [ "/bin/sh", "-c" ]
CMD python3 /app/sync.py --artifacts $ARTIFACTS $SYNCARGS

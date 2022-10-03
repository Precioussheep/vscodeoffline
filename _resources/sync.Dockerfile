FROM python:3.10-alpine as build

WORKDIR /opt/build

# create & install vscoffline package to then provide to second image
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY . .

RUN pip3 install --no-cache-dir --upgrade pip wheel setuptools && \
    pip3 install --no-cache-dir .

FROM python:3.10-alpine as deploy 

RUN apk upgrade --no-cache

COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    ARTIFACTS=/artifacts \
    SYNCARGS=--sync

# setup default artifacts location
RUN mkdir /artifacts

WORKDIR /app

COPY ./vscoffline/sync.py /app/sync.py

CMD python3 sync.py --artifacts $ARTIFACTS $SYNCARGS

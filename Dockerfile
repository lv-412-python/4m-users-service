FROM ubuntu:18.04

RUN apt update -y && \
    apt install -y python3 python3-dev python3-pip libssl-dev libffi-dev

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

COPY ./ ./opt/users-service-repo
WORKDIR /opt/users-service-repo
EXPOSE 5050
RUN make install

ENTRYPOINT ["python3"]
CMD ["setup.py"]

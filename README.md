# Users service [![Build Status](https://travis-ci.org/lv-412-python/4m-users-service.svg?branch=develop)](https://travis-ci.org/lv-412-python/4m-users-service)
## Description
This is the source code of the users service, part of 4m project. This service stores data about users and allows to register and sign in on the Web page

## Technologies
* Python (3.6.8)
* Flask (1.0.3)
* PostgreSQL (10.8)

## Install
For the next steps of service installation, you will need setup of Ubuntu 18.04

### Install and configure PostgreSQL server on your local machine:
```
sudo apt-get install postgresql postgresql-contrib
sudo -u postgres psql postgres

postgres=# \password
Enter new password:
Enter it again:

postgres=# CREATE DATABASE "4m_users_db";
postgres=# CREATE DATABASE "4m_users_db_test";

postgres=# \q
```


### In the project root create venv and install requirements with Make

```
export PYTHONPATH=$PYTHONPATH:/home/.../.../4m-users-service/users_service
```
```
make dev-env
```
#### in case of failure:
```
. venv/bin/activate
pip install -r requirements.txt
```

### Run project

#### run in development mode
```
make dev-env
```

#### run in production mode
```
make prod-env
```


## Project team:
* **Lv-412.WebUI/Python team**:
    - @sikyrynskiy
    - @olya_petryshyn
    - @taraskonchak
    - @OlyaKh00
    - @ement06
    - @iPavliv
    - @Anastasia_Siromska
    - @romichh

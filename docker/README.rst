Docker set-up for testing
=========================

Prerequisites
-------------

* Install `docker` and its `compose` plugin:
  ```sh
  $ sudo apt install docker.io docker-compose-v2
  ```
* Add yourself to the `docker` group (you'll need to logout and login again for it to take effect):
  ```sh
  $ sudo usermod -a -G docker "$USER"
  ```

Run
-------

* ```sh
  $ cargo build
  ```
* In this directory:
  ```sh
  $ docker compose up --build
  ```

Clean-up
--------
```sh
$ docker compose down
```

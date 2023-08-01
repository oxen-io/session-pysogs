# Docker for pysogs production

Build the docker container image with

```
sudo docker build . -f contrib/docker/DockerFile -t pysogs-prod
```

Create docker volumes so we can persist data, config and key from the container to the host between container restarts

```
sudo docker volume create pysogs-data
sudo docker volume create pysogs-config
```

Start the container and mount the volumes with

```
sudo docker run -i  -p 8080:80  -v pysogs-data:/var/lib/session-open-group-server -v pysogs-config:/etc/sogs/ -v pysogs-config:/etc/sogs/ -t pysogs-prod:latest
```

# Docker for pysogs development

The file DockerFile.dev is specifically made for development if you are not running linux.
It lets you create a docker running linux and the pysogs in it even if you are running Macos or Windows.
It creates a docker container with the content of this git repository mounted.
Basically, whatever you edit in this repository will be represented on the docker container. So when you run the container, it will run your code.

> **WARNING**: Not for production use. This docker image is strictly for development use and not supported for production use.

## Build the container image

You need to have docker installed on your computer. Follow the docker documentation for your system first.
Once you can run the hello world from github you should be fine

```
docker run hello-world # this command should print "Hello from Docker!"

```

Then, build the container image for pysogs-dev as

```
git clone git@github.com:oxen-io/session-pysogs.git
cd session-pysogs
sudo docker build . -f contrib/docker/DockerFile.dev -t pysogs-dev
```

Before you can run the container you need to set the base config. You can do so by copying `sogs.ini.sample` to `sogs.ini` and replacing the line with base_url with `base_url = http://localhost`.

> **WARNING**: Not for production use. This docker image is strictly for development use and not supported for production use.

Next, you can run and attach to the container with

```
sudo docker run -i -p 8080:80 -v $PWD:/session-pysogs -t pysogs-dev:latest
```

To start the pysogs once you have a shell in the container do:

```
start-sogs-uwsgi
```

To create a room once you have a shell inside the container do

```
python3 -msogs --add-room fishing --name "Fish Talk"
```

To play with Session and your own development pysogs you need to host you pysogs on a publicly accessible ip.
So this docker needs to be deployed on a server of some sort. Then, you can open the folder remotely (with the ssh vscode extension) or edit the files directly over ssh.
Using the vscode extension, you can also have a shell opened on the remote host, and so be able to quickly stop and restart the `start-sogs-uwsgi` command inside the container on code changes.

More doc at https://github.com/oxen-io/session-pysogs/blob/dev/administration.md#sogs-administration

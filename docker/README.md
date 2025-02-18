# Building pmacct docker containers

This folder contains a `Makefile` to build pmacct docker images. It simplifies
the build process, particularly for [multi-platform images](https://docs.docker.com/build/building/multi-platform/).

## Env. variables

A number of environment variables control the build process (`make`):

* `PLATFORMS`: comma separated list of platforms to pass to `docker buildx
                --platform`. This option is only valid in x86_64 architectures.
               Default: ``
* `BUILD_REGISTRY`: intermediate registry to build multi-platform images.
                    Default: `""` (none).
* `PUSH`: push to docker registry `$PUSH`. The registry should NOT have
          a trailing `/`. Default `""` (don't push).
* `TAGS`: when `PUSH` is defined, it will push all the tags listed in `TAGS`.
          Default: `""`.
* `V`: when set to `1` output is verbose. Default: `""`.

## Building for the host platform (single platform)

To build:

```
make
```

Once completed, `base:_build` and all `<daemon>:_build` images will be loaded to
your local images.

## Multi-platform builds

Building multi-platform images for pmacct using `docker buildx` is a bit tricky.
Today `docker`/`dockerd`'s local image registry doesn't support more than one
platfor (the host's one). In other words, docker buildx's argument `--load`
only works for a single platform matching your host. This limitation might be
lifted in the future, but for now we need to live with it.

`pmacct` daemon Dockerfile files require the base container to build.
Technically, daemon containers are the same container with a different
entrypoint.

TL;DR you will need an auxiliary docker registry that supports multiple
platforms to build multi-platform images.

It is **highly recommended** to use a temporary/adhoc docker registry for the
build process, to avoid clogging the real registries with `_build` tags and
avoid concurrency issues when parallel builds are fired (e.g. from CI).

### Spawning a temporary build registry

Launch a temporary registry:

```
docker run -d -p 5000:5000 --name registry registry:2
```

Use `docker inspect` to get the IP address of the container:

```
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' registry
```

### Launching the build

With the hostname or IP address of the registry above, launch the multi-platform
build process:

```
PLATFORMS="linux/amd64,linux/arm64" \
BUILD_REGISTRY_REPO=<REGISTRY_HOSTNAME_IP>:5000 \
PUSH=<REGISTRY_TO_PUSH> \
TAGS="<list of comma separated tags to push to REGISTRY_TO_PUSH>" \
make
```

Get some :popcorn: for the xcompilation...

### Cleaning up the house

Make sure to tear down and remove the registry:

```
docker stop registry
docker rm registry
```

## Pushing images to a remote repository

Define `PUSH=<registry>` without the trailing `/`. Make sure to add some
meaningful `TAGS`. `_base` tag will NOT be pushed.

## Advanced env. variables

Don't touch unless you know what are you doing:

* `N_WORKERS`: number of parallel workers to pass to make for compiling C/C++
               code. Default: `2`
* `MEMORY`: memory limit passed to `docker buildx`. Default: `8g`.
* `DAEMONS`: list of `DAEMONS` to build the container for. Default: all pmacct
             daemons.

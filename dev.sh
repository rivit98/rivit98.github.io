#!/bin/bash

docker build -t blog-builder -f Dockerfile.dev .
docker run -it --rm -v $(pwd):/w -w /w -p 13337:13337 -u $(id -u):$(id -g) --name blog-builder blog-builder hugo server --disableFastRender --bind 0.0.0.0 -p 13337

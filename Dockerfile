FROM node:alpine
WORKDIR /app
COPY handler.js index.js ./
# No dependencies on purpose: node:http and node:fs are enough, and a sync
# service that holds your data is the last place to want a dependency tree.
RUN echo '{"type":"module"}' > package.json
ENV SYNC_DATA=/data
EXPOSE 8080
VOLUME ["/data"]
CMD ["node", "index.js"]

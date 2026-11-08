ARG APPROVED_NODE_IMAGE
FROM ${APPROVED_NODE_IMAGE}
WORKDIR /app
COPY --chown=65532:65532 server.mjs dreamcatcher.json ./
COPY --chown=65532:65532 dist ./dist
COPY --chown=65532:65532 src/app.js ./dist/app.js
USER 65532:65532
ENV PORT=8080
EXPOSE 8080
CMD ["node","server.mjs"]

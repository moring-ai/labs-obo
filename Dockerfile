# labsOBO | one image for both Bedrock AgentCore runtimes, picked by LABSOBO_ROLE:
#   a1      Agent A1 (T1 from the AWS STS workload JWT, OBO to Defender and to the Jira broker)
#   broker  the Jira broker (validates T_A1_BROKER, holds the Atlassian vault)
# AgentCore runs linux/arm64 and talks HTTP to :8080 (/invocations, /ping).
# No certificates, tokens or sessions go into the image: see .dockerignore.
FROM public.ecr.aws/docker/library/node:22-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY lib ./lib
COPY agents ./agents
COPY .lab/labsOBO.env .lab/lab-state.json ./.lab/
ENV NODE_ENV=production PORT=8080
EXPOSE 8080
USER node
CMD ["node", "agents/entry.mjs"]

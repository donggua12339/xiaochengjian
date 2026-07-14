# 小城笺 AlertManager 飞书告警中转
FROM node:22-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY index.js ./
EXPOSE 5000
CMD ["node", "index.js"]

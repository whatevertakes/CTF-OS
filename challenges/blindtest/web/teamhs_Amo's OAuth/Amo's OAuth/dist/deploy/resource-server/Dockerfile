FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --production
COPY . .
RUN mv ./flag /flag && \
    chmod 444 /flag
EXPOSE 5000
CMD ["node", "server.js"]

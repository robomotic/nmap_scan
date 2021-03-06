FROM node:10-alpine
RUN apk add nmap
RUN apk add nmap-scripts

WORKDIR /app
COPY package.json .
RUN npm install
ADD . /app
EXPOSE 3000
CMD ["node", "index.js"]


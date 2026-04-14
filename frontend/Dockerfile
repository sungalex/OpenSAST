FROM node:20-alpine

ENV NODE_ENV=development \
    VITE_HMR_HOST=0.0.0.0

RUN apk add --no-cache libc6-compat

WORKDIR /app

COPY package.json ./
RUN npm install --no-fund --no-audit --loglevel=info

COPY . .

EXPOSE 5173

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173", "--strictPort"]

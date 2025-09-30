# syntax=docker/dockerfile:1

# --- Builder stage ---
FROM node:18-alpine AS builder
WORKDIR /app

# Install build deps
RUN apk add --no-cache python3 make g++

COPY package*.json ./
COPY nest-cli.json tsconfig*.json ./
RUN npm ci

COPY src ./src
COPY test ./test
COPY .eslint* .prettierrc* ./

RUN npm run build

# --- Production stage ---
FROM node:18-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production

# Only copy package.json for production deps install
COPY package*.json ./
RUN npm ci --omit=dev

# Copy built dist and necessary files
COPY --from=builder /app/dist ./dist
COPY .env* ./

EXPOSE 3000

CMD ["node", "dist/main.js"]



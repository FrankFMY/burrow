# Build stage
FROM oven/bun:1.3 AS builder

WORKDIR /app

COPY package.json bun.lockb* ./
RUN bun install --frozen-lockfile

COPY . .

# Build for production
RUN bun run build

# Runtime stage
FROM oven/bun:1.3-slim

WORKDIR /app

COPY --from=builder /app/build ./build
COPY --from=builder /app/package.json ./

ENV HOST=0.0.0.0
ENV PORT=3000
ENV NODE_ENV=production

EXPOSE 3000

CMD ["bun", "run", "preview", "--host", "--port", "3000"]

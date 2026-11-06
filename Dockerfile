FROM node:24-alpine AS build
WORKDIR /app
COPY package*.json ./
COPY backend/package*.json backend/
COPY frontend/package*.json frontend/
RUN npm install
COPY . .
RUN npm run build

FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package*.json ./
COPY backend/package*.json backend/
COPY frontend/package*.json frontend/
RUN npm install --omit=dev
COPY --from=build /app/backend backend
COPY --from=build /app/frontend/dist frontend/dist
EXPOSE 4000
CMD ["npm", "start"]

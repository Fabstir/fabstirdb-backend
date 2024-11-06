FROM node:20.18.0


WORKDIR /app


COPY . .

RUN yarn


EXPOSE 3001

CMD ["yarn", "start"]
FROM nginx:alpine

# python3 runs the CRCMZ sign-in helper (sso.py, stdlib only)
RUN apk add --no-cache python3

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Copy our nginx config
COPY nginx.conf /etc/nginx/conf.d/slaplayer.conf

# Copy the app
COPY index.html /usr/share/nginx/html/index.html

# CRCMZ sign-in
COPY sso.py /app/sso.py
COPY entrypoint.sh /entrypoint.sh

EXPOSE 80

CMD ["/entrypoint.sh"]

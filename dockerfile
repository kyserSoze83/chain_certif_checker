FROM python:3.9

WORKDIR /app

RUN apt-get update
ADD ./www/ ./www/
ADD ./validate-cert-chain.py ./validate-cert-chain.py
ADD ./vclib.py ./vclib.py
ADD ./requirements.txt ./requirements.txt

RUN mkdir ./certs

RUN chmod 777 ./certs

RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /app/www

EXPOSE 5000

CMD python server.py

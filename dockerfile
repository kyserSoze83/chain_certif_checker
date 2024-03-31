FROM python:3.9

WORKDIR /app

COPY ./www/ ./www/
COPY ./validate-cert-chain.py ./validate-cert-chain.py
COPY ./vclib.py ./vclib.py
COPY ./requirements.txt ./requirements.txt

RUN mkdir cert

RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["python", "./www/server.py"]

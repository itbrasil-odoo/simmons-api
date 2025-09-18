# Dockerfile para simmons-api
FROM python:3.11-slim

# Diretório de trabalho
WORKDIR /app

# Copia os arquivos de requirements e instala dependências
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copia o restante da aplicação
COPY . .

# Comando padrão (ajuste conforme o entrypoint real do seu app)
CMD ["python", "gerenciador_servicos.py"]

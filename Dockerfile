# Dockerfile para produção - simmons-api
FROM python:3.11-slim

# Diretório de trabalho
WORKDIR /app

# Copia os arquivos de requirements e instala dependências
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
	&& pip install --no-cache-dir gunicorn

# Copia o restante da aplicação
COPY . .

# Comando padrão para produção usando Gunicorn
# Ajuste "app" se o nome do objeto Flask for diferente
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "gerenciador_servicos:app"]

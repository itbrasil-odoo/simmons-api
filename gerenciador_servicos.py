# -*- coding: utf-8 -*-

# =======================================================================
# ======================== IMPORTAÇÕES E SETUP ==========================
# =======================================================================
import os
import json
import math
import time
import requests
import logging
import re
import jwt
import threading
from datetime import datetime, timedelta
from functools import wraps

from bson import ObjectId
from dotenv import load_dotenv, find_dotenv, set_key
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from pydantic import BaseModel, Field, ValidationError
from typing import Optional, Dict, List
from werkzeug.security import generate_password_hash, check_password_hash
from colorama import Fore, Style, init

init(autoreset=True)
load_dotenv()

# =======================================================================
# ========================== CONFIGURAÇÃO DO LOGGER =======================
# =======================================================================
class ColorFormatter(logging.Formatter):
    LOG_LEVEL_COLORS = { logging.DEBUG: Fore.CYAN, logging.INFO: Fore.GREEN, logging.WARNING: Fore.YELLOW, logging.ERROR: Fore.RED, logging.CRITICAL: Fore.MAGENTA }
    HIGHLIGHT_RULES = {
        r"\b(sucesso|integrado com sucesso|encontrada|iniciado|rodando)\b": Style.BRIGHT + Fore.GREEN,
        r"\b(Ignorando|Aguardando|processado|parado)\b": Style.BRIGHT + Fore.YELLOW,
        r"\b(Erro|falhou|inválido|Falha|parando)\b": Style.BRIGHT + Fore.RED,
        r"\b([a-zA-Z0-9]{15,})\b": Style.BRIGHT + Fore.CYAN,
        r"'([^']*)'": Fore.MAGENTA,
    }
    def format(self, record):
        log_color = self.LOG_LEVEL_COLORS.get(record.levelno, Fore.WHITE)
        message = super().format(record)
        for pattern, color in self.HIGHLIGHT_RULES.items():
            message = re.sub(pattern, lambda m: f"{color}{m.group(0)}{log_color}", message, flags=re.IGNORECASE)
        return f"{log_color}{message}{Style.RESET_ALL}"

logger = logging.getLogger("ServiceManager")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = ColorFormatter("[%(asctime)s] [%(levelname)s] - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
handler.setFormatter(formatter)
if not logger.handlers: logger.addHandler(handler)

# =======================================================================
# ======================== FLASK APP E CONFIGURAÇÕES ======================
# =======================================================================
app = Flask(__name__)
CORS(app)

app.config["SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
app.config["MONGO_URI"] = os.environ.get("MONGO_URI")
app.config["MONGO_DB_NAME"] = os.environ.get("MONGO_DB_NAME")
app.config["GOOGLE_API_KEY"] = os.environ.get("GOOGLE_API_KEY")
META_PAGE_ACCESS_TOKEN = os.environ.get("META_PAGE_ACCESS_TOKEN")
META_GRAPH_API_URL = "https://graph.facebook.com/v18.0"
F1SALES_API_URL = os.environ.get("F1SALES_API_URL")

POLLING_INTERVAL_SECONDS = 10
F1SALES_RETRY_COUNT = 3
F1SALES_RETRY_DELAY = 5

# =======================================================================
# ======================== CONEXÃO COM BANCO DE DADOS =====================
# =======================================================================
try:
    client = MongoClient(app.config["MONGO_URI"])
    db = client[app.config["MONGO_DB_NAME"]]
    users_collection = db.users
    stores_collection = db.stores
    processed_leads_collection = db.processed_leads
    leads_collection = db.leads
    form_configs_collection = db.form_configs
    logger.info("Conexão com o MongoDB estabelecida com sucesso.")
except Exception as e:
    logger.critical(f"Erro fatal ao conectar com o MongoDB: {e}"); exit(1)

# =======================================================================
# ======================== MODELOS DE DADOS (PYDANTIC) ===================
# =======================================================================
class Coordenadas(BaseModel): lat: float; lng: float
class StoreModel(BaseModel): id: Optional[str] = Field(default=None, alias='_id'); f1code: str; nome: str; coordenadas: Coordenadas
class LeadCustomerModel(BaseModel): name: str; phone: str; email: str; cep: str
class PublicLeadPayload(BaseModel): customer: LeadCustomerModel; product: Dict[str, str]; source: Dict[str, str]; message: str; description: str

class FormConfigModel(BaseModel):
    id: Optional[str] = Field(default=None, alias='_id')
    form_id: str
    form_name: str

# =======================================================================
# ======================== SERVIÇOS E LÓGICA DE NEGÓCIO ===================
# =======================================================================

# <<< INTEGRADO DO APP.PY: Versão mais robusta do GeolocationService >>>
class GeolocationService:
    def get_coords_from_cep(self, cep: str) -> Optional[Coordenadas]:
        try:
            cep_numerico = ''.join(filter(str.isdigit, cep))
            if len(cep_numerico) != 8: return None
            # Etapa 1: ViaCEP
            via_cep_res = requests.get(f"https://viacep.com.br/ws/{cep_numerico}/json/")
            via_cep_res.raise_for_status(); cep_data = via_cep_res.json()
            if cep_data.get("erro"): return None
            # Etapa 2: Google Geocoding com o endereço do ViaCEP
            endereco = f"{cep_data['logradouro']}, {cep_data['bairro']}, {cep_data['localidade']} - {cep_data['uf']}"
            params = {"address": endereco, "key": app.config["GOOGLE_API_KEY"]}
            geo_res = requests.get("https://maps.googleapis.com/maps/api/geocode/json", params=params)
            geo_res.raise_for_status(); geo_data = geo_res.json()
            if geo_data.get("status") == "OK":
                loc = geo_data["results"][0]["geometry"]["location"]
                return Coordenadas(lat=loc["lat"], lng=loc["lng"])
            return None
        except requests.RequestException as e:
            logger.error(f"Erro ao chamar API externa de geolocalização: {e}")
            return None
    def _haversine_distance(self, c1: Coordenadas, c2: Coordenadas) -> float: R = 6371; d_lat = math.radians(c2.lat - c1.lat); d_lon = math.radians(c2.lng - c1.lng); a = math.sin(d_lat/2)**2 + math.cos(math.radians(c1.lat)) * math.cos(math.radians(c2.lat)) * math.sin(d_lon/2)**2; c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a)); return R * c
    def find_nearest_store(self, client_coords: Coordenadas) -> Optional[dict]:
        all_stores = list(stores_collection.find({}))
        if not all_stores: return None
        distances = [(self._haversine_distance(client_coords, Coordenadas(**s["coordenadas"])), s) for s in all_stores if "coordenadas" in s and s.get("coordenadas")]
        if not distances: return None
        distances.sort(key=lambda x: x[0])
        dist, store = distances[0]
        logger.info(f"Loja mais próxima encontrada: '{store['nome']}' ({store['f1code']}) a {dist:.2f} km.")
        # <<< INTEGRADO DO APP.PY: Lógica de fallback para lojas muito distantes >>>
        DISTANCE_THRESHOLD_KM = 150
        if dist > DISTANCE_THRESHOLD_KM:
            logger.warning(f"A loja mais próxima está a mais de {DISTANCE_THRESHOLD_KM}km. Buscando vendedor de fallback...")
            # Idealmente, o f1code de fallback também seria uma variável de ambiente
            fallback_store = stores_collection.find_one({"f1code": "erik.santos@flex.es"})
            if fallback_store: logger.info("Vendedor de fallback 'erik.santos@flex.es' encontrado.")
            return fallback_store
        return store


# <<< VERSÃO HÍBRIDA: Payload do app.py + Retentativas do gerenciador_servicos.py >>>
class F1SalesService:
    HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    def send_lead_with_retry(self, payload: PublicLeadPayload, store_f1code: Optional[str] = None, max_retries=F1SALES_RETRY_COUNT) -> bool:
        if not F1SALES_API_URL:
            logger.error("[F1Sales] Envio falhou: F1SALES_API_URL não configurada.")
            return False
        # <<< INTEGRADO DO APP.PY: Estrutura de payload mais detalhada >>>
        lead_payload = {
            "lead": {
                "customer": { "name": payload.customer.name, "phone": payload.customer.phone, "email": payload.customer.email, "address": {"cep": payload.customer.cep} },
                "product": payload.product, "source": payload.source, "message": payload.message, "description": payload.description,
            }
        }
        for attempt in range(max_retries):
            try:
                logger.info(f"[F1Sales] Tentativa {attempt + 1}/{max_retries} de enviar o lead '{payload.customer.name}'...")
                res = requests.post(f"{F1SALES_API_URL}/leads", json=lead_payload, headers=self.HEADERS)
                res.raise_for_status()
                f1_lead_id = res.json().get("data", {}).get("id")
                if store_f1code and f1_lead_id:
                    assign_payload = {"lead": {"salesman": {"email": store_f1code}}}
                    put_res = requests.put(f"{F1SALES_API_URL}/leads/{f1_lead_id}", json=assign_payload, headers=self.HEADERS)
                    put_res.raise_for_status()
                    logger.info(f"[F1Sales] Atribuição para a loja '{store_f1code}' realizada com sucesso.")
                return True
            except requests.RequestException as e:
                logger.error(f"[F1Sales] Tentativa {attempt + 1} falhou: {e}")
                if e.response is not None: logger.error(f"[F1Sales] Resposta do erro: {e.response.text}")
                if attempt < max_retries - 1: time.sleep(F1SALES_RETRY_DELAY)
        return False

# =======================================================================
# ======================== CLASSE DE POLLING DE LEADS =====================
# =======================================================================
class MetaLeadPoller:
    def __init__(self, geo_service: GeolocationService, f1_service: F1SalesService): self.geo_service = geo_service; self.f1_service = f1_service; self._is_running = False; self._thread = None; self._lock = threading.Lock()
    def get_status(self):
        with self._lock: return { "running": self._is_running, "status": "Rodando" if self._is_running else "Parado" }
    def start(self):
        with self._lock:
            if self._is_running: return False
            self._is_running = True; self._thread = threading.Thread(target=self.run, daemon=True); self._thread.start(); logger.info("Serviço de polling iniciado."); return True
    def stop(self):
        with self._lock:
            if not self._is_running: return False
            self._is_running = False; logger.info("Sinal de parada enviado ao poller...")
        if self._thread: self._thread.join(timeout=POLLING_INTERVAL_SECONDS + 5); logger.info("Serviço de polling parado.")
        return True
    def run(self):
        logger.info("THREAD DE POLLING DE LEADS INICIADA")
        while self._is_running:
            try:
                self.fetch_and_process_leads()
                if not self._is_running: break
                logger.info(f"Ciclo concluído. Aguardando {POLLING_INTERVAL_SECONDS} segundos...")
                for _ in range(POLLING_INTERVAL_SECONDS):
                    if not self._is_running: break
                    time.sleep(1)
            except Exception as e: logger.critical(f"Erro crítico no loop do poller: {e}. Reiniciando em 30 segundos."); time.sleep(30)
        logger.info("Loop de polling encerrado.")
    def fetch_and_process_leads(self):
        form_configs_cursor = form_configs_collection.find({})
        current_form_config = {form['form_id']: form['form_name'] for form in form_configs_cursor}
        if not current_form_config: logger.warning("Nenhum formulário configurado no DB."); return
        for form_id, form_name in current_form_config.items():
            if not self._is_running: return
            logger.info(f"Verificando leads em '{form_name}' (ID: {form_id})")
            try:
                url = f"{META_GRAPH_API_URL}/{form_id}/leads"
                params = {'access_token': META_PAGE_ACCESS_TOKEN, 'fields': 'field_data,created_time,campaign_name', 'limit': 100}
                response = requests.get(url, params=params)
                response.raise_for_status()
                leads_raw = response.json().get("data", [])
                if not leads_raw: logger.info(f"Nenhum lead novo em '{form_name}'."); continue
                for lead_data in leads_raw:
                    if not self._is_running: return
                    lead_id = lead_data.get("id")
                    if processed_leads_collection.find_one({"lead_id": lead_id}): continue
                    mapped_data = {f['name']: f['values'][0] for f in lead_data.get("field_data", [])}
                    lead_name = mapped_data.get("full_name", "N/A")
                    cep_lead = mapped_data.get("post_code") or mapped_data.get("cep")
                    if not cep_lead: logger.warning(f"Lead '{lead_name}' (ID: {lead_id}) ignorado por não conter CEP."); continue
                    
                    logger.info(f"--- Processando lead: '{lead_name}' (ID: {lead_id}) ---")
                    client_coords = self.geo_service.get_coords_from_cep(cep_lead)
                    nearest_store = self.geo_service.find_nearest_store(client_coords) if client_coords else None
                    store_f1code = nearest_store.get("f1code") if nearest_store else None
                    
                    payload = PublicLeadPayload(
                        customer=LeadCustomerModel(
                            name=lead_name,
                            phone=mapped_data.get("phone_number", ""),
                            email=mapped_data.get("email", ""),
                            cep=cep_lead
                        ),
                        product={"name": f"Produto Meta - {form_name}"},
                        source={
                            "origin": f"Meta Lead Ad - {form_name}",
                            "campaign": lead_data.get("campaign_name", "N/A")
                        },
                        message=f"Lead do formulário Meta: '{form_name}'. CEP: {cep_lead}.",
                        description=f"Lead ID Meta: {lead_id} | Loja Atribuída: {store_f1code or 'N/A'}"
                    )
                    send_success = self.f1_service.send_lead_with_retry(payload, store_f1code)
                    db_status = "integrado" if send_success else "erro"
                    leads_collection.insert_one({
                        "meta_lead_id": lead_id,
                        "data": payload.model_dump(),
                        "status": db_status,
                        "processed_at": datetime.utcnow()
                    })
                    processed_leads_collection.insert_one({
                        "lead_id": lead_id,
                        "processed_at": datetime.utcnow()
                    })
                    logger.info(f"✅ Lead '{lead_name}' integrado!" if send_success else f"❌ Falha ao integrar o lead '{lead_name}'.")
            except Exception as e:
                logger.error(f"Erro ao processar formulário '{form_name}': {e}", exc_info=True)

# =======================================================================
# ======================== INSTÂNCIAS DOS SERVIÇOS =======================
# =======================================================================
geolocation_service = GeolocationService()
f1_sales_service = F1SalesService()
meta_lead_poller = MetaLeadPoller(geolocation_service, f1_sales_service)

# =======================================================================
# ======================== DECORATORS E HELPERS =========================
# =======================================================================
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").split(" ")[-1]
        if not token: return jsonify({"message": "Token está faltando!"}), 401
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"]); current_user = users_collection.find_one({"_id": ObjectId(data["user_id"])})
            if not current_user: return jsonify({"message": "Usuário do token não encontrado."}), 401
        except: return jsonify({"message": "Token inválido!"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(current_user, *args, **kwargs):
        if current_user.get("role") != "admin": return jsonify({"message": "Acesso negado: Requer privilégios de administrador."}), 403
        return f(current_user, *args, **kwargs)
    return decorated

def serialize_doc(doc):
    if doc and "_id" in doc: doc["_id"] = str(doc["_id"])
    return doc

# =======================================================================
# ============================ ROTAS DA API =============================
# =======================================================================
@app.route("/", methods=["GET"])
def home(): return jsonify({"status": "API Simmons Leads - Sistema Unificado", "version": "5.0.0"})

# --- ROTAS DE AUTENTICAÇÃO E USUÁRIOS ---
@app.route("/register", methods=["POST"])
@admin_required
def register(current_user):
    data = request.get_json(); username, password, role = data.get("username"), data.get("password"), data.get("role", "user")
    if not username or not password: return jsonify({"message": "Usuário e senha são obrigatórios."}), 400
    if users_collection.find_one({"username": username}): return jsonify({"message": "Este nome de usuário já existe."}), 409
    users_collection.insert_one({"username": username, "password": generate_password_hash(password), "role": role})
    return jsonify({"message": "Usuário registrado com sucesso!"}), 201

@app.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password: return jsonify({"message": "Login via Basic Auth é necessário."}), 401
    user = users_collection.find_one({"username": auth.username})
    if not user or not check_password_hash(user["password"], auth.password): return jsonify({"message": "Usuário ou senha inválidos."}), 401
    token = jwt.encode({ "user_id": str(user["_id"]), "role": user.get("role", "user"), "exp": datetime.utcnow() + timedelta(hours=24) }, app.config["SECRET_KEY"], algorithm="HS256")
    return jsonify({"token": token})

# --- ROTAS DE LOJAS (STORES) - CRUD COMPLETO ---

@app.route("/stores", methods=["POST"])
@admin_required
def create_store(current_user):
    try:
        store_data = StoreModel(**request.get_json())
        if stores_collection.find_one({"f1code": store_data.f1code}): return jsonify({"message": f"Loja com f1code '{store_data.f1code}' já existe."}), 409
        result = stores_collection.insert_one(store_data.model_dump(by_alias=True, exclude={'id'}))
        return jsonify(serialize_doc(stores_collection.find_one({"_id": result.inserted_id}))), 201
    except ValidationError as e: return jsonify({"message": "Dados inválidos", "errors": e.errors()}), 400

@app.route("/stores", methods=["GET"])
@token_required
def get_all_stores(current_user):
    return jsonify([serialize_doc(store) for store in stores_collection.find()]), 200

# <<< INTEGRADO DO APP.PY: Rota para encontrar a loja mais próxima >>>
@app.route("/stores/find-nearest", methods=["POST"])
def find_nearest_store_route():
    data = request.get_json(); cep = data.get("cep")
    if not cep: return jsonify({"message": "O campo 'cep' é obrigatório."}), 400
    try:
        client_coords = geolocation_service.get_coords_from_cep(cep)
        if not client_coords: return jsonify({"message": "CEP inválido ou não foi possível obter as coordenadas."}), 400
        nearest_store = geolocation_service.find_nearest_store(client_coords)
        if not nearest_store: return jsonify({"message": "Nenhuma loja foi encontrada na região."}), 404
        return jsonify(serialize_doc(nearest_store)), 200
    except Exception as e: return jsonify({"message": "Erro interno ao buscar a loja.", "error": str(e)}), 500

# <<< INTEGRADO DO APP.PY: Rota para atualizar uma loja >>>
@app.route("/stores/<store_id>", methods=["PUT"])
@admin_required # Adicionada segurança a esta rota
def update_store(current_user, store_id):
    try:
        store_data = StoreModel(**request.get_json())
        update_payload = store_data.model_dump(by_alias=True, exclude_unset=True, exclude={'id'})
        result = stores_collection.update_one({"_id": ObjectId(store_id)}, {"$set": update_payload})
        if result.matched_count: return jsonify(serialize_doc(stores_collection.find_one({"_id": ObjectId(store_id)}))), 200
        return jsonify({"message": "Loja não encontrada."}), 404
    except ValidationError as e: return jsonify({"message": "Dados inválidos", "errors": e.errors()}), 400

# <<< INTEGRADO DO APP.PY: Rota para deletar uma loja >>>
@app.route("/stores/<store_id>", methods=["DELETE"])
@admin_required # Adicionada segurança a esta rota
def delete_store(current_user, store_id):
    try:
        result = stores_collection.delete_one({"_id": ObjectId(store_id)})
        if result.deleted_count: return jsonify({"message": "Loja deletada com sucesso."}), 200
        return jsonify({"message": "Loja não encontrada."}), 404
    except: return jsonify({"message": "ID inválido."}), 400

# --- ROTAS DE LEADS (MANUAIS) ---
@app.route("/leads/assign", methods=["POST"])
@token_required # Rota protegida para criação manual de leads
def create_and_assign_lead(current_user):
    try:
        payload = PublicLeadPayload(**request.get_json())
        client_coords = geolocation_service.get_coords_from_cep(payload.customer.cep)
        if not client_coords: return jsonify({"message": "CEP inválido."}), 400
        nearest_store = geolocation_service.find_nearest_store(client_coords)
        if not nearest_store: return jsonify({"message": "Nenhuma loja encontrada."}), 404
        success = f1_sales_service.send_lead_with_retry(payload, nearest_store["f1code"])
        if success: return jsonify({"message": "Lead enviado e atribuído com sucesso!", "assigned_store": serialize_doc(nearest_store) }), 201
        return jsonify({"message": "Falha ao enviar o lead."}), 500
    except ValidationError as e: return jsonify({"message": "Dados do lead inválidos", "errors": e.errors()}), 400

# --- ROTAS DE CONTROLE DO POLLER ---
@app.route('/poller/status', methods=['GET'])
@admin_required
def get_poller_status(current_user): return jsonify(meta_lead_poller.get_status()), 200
@app.route('/poller/start', methods=['POST'])
@admin_required
def start_poller(current_user):
    if meta_lead_poller.start(): return jsonify({"message": "Serviço de polling iniciado."}), 200
    return jsonify({"message": "Serviço de polling já estava em execução."}), 409
@app.route('/poller/stop', methods=['POST'])
@admin_required
def stop_poller(current_user):
    if meta_lead_poller.stop(): return jsonify({"message": "Serviço de polling parado."}), 200
    return jsonify({"message": "Serviço de polling já estava parado."}), 409

# --- ROTAS DE GERENCIAMENTO (FORMULÁRIOS E .ENV) ---
@app.route('/forms', methods=['POST'])
@admin_required
def add_form_config(current_user):
    try:
        data = FormConfigModel(**request.get_json())
        if form_configs_collection.find_one({"form_id": data.form_id}): return jsonify({"message": f"O formulário com ID '{data.form_id}' já existe."}), 409
        result = form_configs_collection.insert_one(data.model_dump(exclude={'id'})); return jsonify(serialize_doc(form_configs_collection.find_one({"_id": result.inserted_id}))), 201
    except ValidationError as e: return jsonify({"message": "Dados inválidos", "errors": e.errors()}), 400
@app.route('/forms', methods=['GET'])
@admin_required
def get_all_form_configs(current_user): return jsonify([serialize_doc(form) for form in form_configs_collection.find()]), 200

# Adicione estas rotas ao seu arquivo .py

@app.route('/forms/<form_id>', methods=['PUT'])
@admin_required
def update_form_config(current_user, form_id):
    """Atualiza o nome de uma configuração de formulário."""
    try:
        data = request.get_json()
        if 'form_name' not in data:
            return jsonify({"message": "O campo 'form_name' é obrigatório."}), 400
        
        update_data = {"form_name": data["form_name"]}
        result = form_configs_collection.update_one({"_id": ObjectId(form_id)}, {"$set": update_data})
        
        if result.matched_count == 0:
            return jsonify({"message": "Formulário não encontrado."}), 404
            
        updated_form = form_configs_collection.find_one({"_id": ObjectId(form_id)})
        return jsonify(serialize_doc(updated_form)), 200
    except Exception:
        return jsonify({"message": "ID de formulário inválido."}), 400

@app.route('/forms/<form_id>', methods=['DELETE'])
@admin_required
def delete_form_config(current_user, form_id):
    """Remove uma configuração de formulário."""
    try:
        result = form_configs_collection.delete_one({"_id": ObjectId(form_id)})
        if result.deleted_count == 0:
            return jsonify({"message": "Formulário não encontrado."}), 404
        return jsonify({"message": "Formulário removido com sucesso."}), 200
    except Exception:
        return jsonify({"message": "ID de formulário inválido."}), 400

MANAGEABLE_ENV_VARS = ["MONGO_URI", "MONGO_DB_NAME", "JWT_SECRET_KEY", "GOOGLE_API_KEY", "META_PAGE_ACCESS_TOKEN", "F1SALES_API_URL"]
SENSITIVE_KEYS = ["MONGO_URI", "JWT_SECRET_KEY", "GOOGLE_API_KEY", "META_PAGE_ACCESS_TOKEN", "F1SALES_API_URL"]
@app.route('/settings/env', methods=['GET'])
@admin_required
def get_env_variables(current_user):
    env_vars = {}
    for key in MANAGEABLE_ENV_VARS:
        value = os.getenv(key)
        if key in SENSITIVE_KEYS and value: env_vars[key] = f"******{value[-4:]}"
        else: env_vars[key] = value
    return jsonify(env_vars), 200
@app.route('/settings/env', methods=['POST'])
@admin_required
def set_env_variables(current_user):
    data = request.get_json()
    if not isinstance(data, dict): return jsonify({"message": "Corpo da requisição deve ser um JSON."}), 400
    env_file_path = find_dotenv();
    if not env_file_path: return jsonify({"message": "Arquivo .env não encontrado."}), 500
    updated_keys = [key for key, value in data.items() if key in MANAGEABLE_ENV_VARS and set_key(env_file_path, key, str(value))]
    return jsonify({ "message": "Variáveis de ambiente atualizadas.", "updated_keys": updated_keys, "warning": "É NECESSÁRIO REINICIAR O SERVIÇO para que as alterações tenham efeito." }), 200

# =======================================================================
# ======================== INICIALIZAÇÃO DO SERVIDOR ====================
# =======================================================================
if __name__ == "__main__":
    logger.info("==================================================")
    logger.info("      INICIANDO SISTEMA UNIFICADO DE LEADS     ")
    logger.info("==================================================")
    if not F1SALES_API_URL: logger.error("!!! ATENÇÃO: F1SALES_API_URL não está definida no .env !!!")
    logger.warning("O serviço de polling está PARADO. Use a rota POST /poller/start para iniciá-lo.")
    app.run(host='0.0.0.0', port=5000, debug=True)
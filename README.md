# 🔓 A01 - Quebra de Controle de Acesso (Broken Access Control)

## 📖 Teoria (20%)

Broken Access Control ocorre quando usuários conseguem agir **fora das suas permissões pretendidas**. É a vulnerabilidade #1 do OWASP desde 2021.

**Impacto:** Acesso não autorizado a dados, modificação ou destruição de informações, execução de funções privilegiadas.

---

## 💻 Prática (80%)

### 🔴 Código VULNERÁVEL

#### Exemplo 1 — IDOR (Insecure Direct Object Reference)
```python
# Flask — VULNERÁVEL
from flask import Flask, request, jsonify

app = Flask(__name__)

users = {
    1: {"name": "Alice", "email": "alice@example.com", "role": "user"},
    2: {"name": "Bob",   "email": "bob@example.com",   "role": "user"},
    3: {"name": "Admin", "email": "admin@example.com", "role": "admin"},
}

@app.route("/api/user/<int:user_id>")
def get_user(user_id):
    # ❌ Qualquer um pode ver qualquer perfil
    user = users.get(user_id)
    if user:
        return jsonify(user)
    return jsonify({"error": "User not found"}), 404
```

**Como explorar:**
```bash
# Atacante autenticado como user_id=1 acessa dados de outros usuários
curl http://localhost:5000/api/user/2
curl http://localhost:5000/api/user/3  # Dados do admin!
```

---

#### Exemplo 2 — Escalada de Privilégio via Parâmetro
```javascript
// Node.js + Express — VULNERÁVEL
app.post('/api/update-role', (req, res) => {
  const { userId, role } = req.body;
  // ❌ Qualquer usuário pode alterar qualquer role
  db.query('UPDATE users SET role = ? WHERE id = ?', [role, userId]);
  res.json({ success: true });
});
```

**Como explorar:**
```bash
curl -X POST http://localhost:3000/api/update-role \
  -H "Content-Type: application/json" \
  -d '{"userId": 1, "role": "admin"}'
```

---

### 🟢 Código SEGURO

#### Correção 1 — IDOR com autorização
```python
# Flask — SEGURO
from flask import Flask, request, jsonify, session
from functools import wraps

app = Flask(__name__)

def require_own_resource_or_admin(f):
    @wraps(f)
    def decorated(user_id, *args, **kwargs):
        current_user = session.get("user_id")
        current_role = session.get("role")

        # ✅ Só acessa o próprio perfil, ou admin acessa qualquer um
        if current_user != user_id and current_role != "admin":
            return jsonify({"error": "Access denied"}), 403
        return f(user_id, *args, **kwargs)
    return decorated

@app.route("/api/user/<int:user_id>")
@require_own_resource_or_admin
def get_user(user_id):
    user = users.get(user_id)
    if user:
        return jsonify(user)
    return jsonify({"error": "User not found"}), 404
```

#### Correção 2 — Role-Based Access Control (RBAC)
```python
# Middleware de autorização robusto
from enum import Enum

class Role(Enum):
    USER  = "user"
    MOD   = "moderator"
    ADMIN = "admin"

PERMISSIONS = {
    Role.USER:  ["read:own_profile", "update:own_profile"],
    Role.MOD:   ["read:own_profile", "update:own_profile", "read:all_profiles"],
    Role.ADMIN: ["read:own_profile", "update:own_profile",
                 "read:all_profiles", "delete:profile", "update:roles"],
}

def has_permission(user_role: str, required_permission: str) -> bool:
    role = Role(user_role)
    return required_permission in PERMISSIONS.get(role, [])

# Uso na rota
@app.route("/api/admin/users")
def list_all_users():
    user_role = session.get("role")
    if not has_permission(user_role, "read:all_profiles"):
        return jsonify({"error": "Forbidden"}), 403
    return jsonify(list(users.values()))
```

---

### 🧪 Lab Prático — Docker

```bash
# Suba o ambiente vulnerável
docker run -d -p 8080:80 webgoat/webgoat-8.0

# Acesse: http://localhost:8080/WebGoat
# Vá em: Access Control > Insecure Direct Object References
```

---

### 🛠️ Ferramentas de Detecção

```bash
# Burp Suite — Interceptar e modificar IDs
# 1. Configure proxy: 127.0.0.1:8080
# 2. Navegue autenticado como user_id=5
# 3. Intercepte a request GET /api/user/5
# 4. Altere para GET /api/user/1, /api/user/2...

# FFUF — Força bruta em IDs
ffuf -u http://target.com/api/user/FUZZ \
     -w numbers.txt \
     -H "Cookie: session=SEU_TOKEN" \
     -mc 200

# Nuclei — Templates prontos
nuclei -u http://target.com -t vulnerabilities/idor/
```

---

### ✅ Checklist de Prevenção

- [ ] Implementar controle de acesso server-side (nunca client-side)
- [ ] Usar IDs não previsíveis (UUID em vez de inteiros sequenciais)
- [ ] Validar permissão em CADA endpoint
- [ ] Logar falhas de controle de acesso
- [ ] Testes unitários para cada nível de permissão
- [ ] Rate limiting em endpoints sensíveis

```python
# Use UUID em vez de IDs sequenciais
import uuid

def create_user():
    user_id = str(uuid.uuid4())  # "a3f2c1d4-..." em vez de 1, 2, 3...
    # Muito mais difícil de enumerar
```

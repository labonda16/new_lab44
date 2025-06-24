from flask import Flask, render_template, request, redirect, session, url_for, jsonify, flash
import docker
import sqlite3
import os
import socket
import subprocess
import threading
import time
from datetime import datetime, timedelta
import json
import os
import yaml


import subprocess
import os

def start_monitoring_stack():
    compose_file = os.path.join(os.path.dirname(__file__), 'docker-compose.yml')

    try:
        # Vérifie si les conteneurs Grafana/Prometheus tournent déjà
        result = subprocess.run(
            ["docker", "compose", "-f", compose_file, "ps", "--services", "--filter", "status=running"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        running_services = result.stdout.strip().splitlines()

        # Liste des services qu'on veut surveiller
        expected_services = {"grafana", "prometheus", "cadvisor"}

        if not expected_services.issubset(set(running_services)):
            print("[INFO] Lancement du stack de monitoring (Grafana, Prometheus, cAdvisor)...")
            subprocess.run(
                ["docker", "compose", "-f", compose_file, "up", "-d"],
                check=True
            )
        else:
            print("[INFO] Le stack de monitoring est déjà actif.")
    except Exception as e:
        print(f"[ERREUR] Impossible de lancer le stack de monitoring : {e}")

# Lance le monitoring avant Flask
start_monitoring_stack()


"""
-Création de l'application Flask
-Définition d'une session persistante de 3 heures
-Définition de la clé secrète
-Connexion au moteur Docker local"""
app = Flask(__name__)
app.permanent_session_lifetime = timedelta(hours=3)
app.secret_key = "supersecretkey"
client = docker.from_env()



"""
Créer une base users.db si elle n'existe pas,
avec une table users :
-username, password, is_admin (1 si admin), user_index
-Le compte admin par défaut avec index 0"""
if not os.path.exists("users.db"):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            user_index INTEGER UNIQUE
        )
    """)
    # admin a l’index 0
    c.execute("INSERT INTO users (username, password, is_admin, user_index) VALUES (?, ?, ?, ?)", 
              ("admin", "admin", 1, 0))
    conn.commit()
    conn.close()

# Load services from JSON file
SERVICES_FILE = 'services.json'

"""Charger les services Docker depuis un fichier services.json"""
def load_services():
    if os.path.exists(SERVICES_FILE):
        with open(SERVICES_FILE, 'r') as f:
            return json.load(f)
    else:
        return ("services.json not found, please create or import it.")
    return {}

"""Permet d'enregistrer la config (image, ports, etc.)"""
def save_services():
    with open(SERVICES_FILE, 'w') as f:
        json.dump(SERVICES, f, indent=4)

"""SERVICES est un dictionnaire global contenant 
tous les services disponibles"""
SERVICES = load_services()

"""Obtenir user_index à partir du nom d'utilisateur.
Si l'utilisateur n'existe pas, retourne None."""
def get_user_index(username):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT user_index FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

"""Obtenir les infos d'un utilisateur"""
def get_user(username):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT username, password, is_admin FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    return row if row else None

"""Lister tous les utilisateurs non-admins (pour le dashboard admin)"""
def get_all_users():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE is_admin=0")
    users = [row[0] for row in c.fetchall()]
    conn.close()
    return users

"""
Route d’accueil pour se connecter
Si le mot de passe est correct → redirige vers /dashboar"""
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)
        if user and user[1] == password:
            session['user'] = username
            session['admin'] = user[2]
            session.permanent = True
            return redirect('/dashboard')
    return render_template('login.html')
    
"""
Vérifie si un port est libre 
(important pour éviter les conflits lors du lancement d’un service)"""
def is_port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('0.0.0.0', port)) != 0

"""
Renvoie l’état (Running, Stopped, Not Found)
de chaque conteneur de l’utilisateur courant 
(pour affichage dans le dashboard)"""
@app.route("/api/service-status")
def service_status():
    status = {}
    for service_name in SERVICES:
        user = session.get('user')
        container_name = f"{service_name}-{user}"
        try:
            container = client.containers.get(container_name)
            status[service_name] = "Running" if container.status == "running" else "Stopped"
        except:
            status[service_name] = "Not Found"
    return jsonify(status)



def calculate_cpu_percent(stats):
    try:
        cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - stats["precpu_stats"]["cpu_usage"]["total_usage"]
        system_delta = stats["cpu_stats"]["system_cpu_usage"] - stats["precpu_stats"]["system_cpu_usage"]
        if system_delta > 0.0 and cpu_delta > 0.0:
            return (cpu_delta / system_delta) * len(stats["cpu_stats"]["cpu_usage"].get("percpu_usage", [])) * 100.0
    except Exception:
        pass
    return 0.0


"""
Admin : affiche liste des utilisateurs + services
Étudiant : affiche ses services personnels"""
from flask import request

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')

    if session.get('admin'):
        client = docker.from_env()
        containers = client.containers.list(all=True)
        container_info = []
        users = get_all_users()

        for container in client.containers.list():
            if any(container.name.endswith(f"-{user}") for user in users):  # 🔍 Conteneurs étudiants
                stats = container.stats(stream=False)
                cpu_percent = calculate_cpu_percent(stats)
                mem_usage = stats["memory_stats"]["usage"] / (1024 * 1024)

                # Ports + URL d’accès
                ports = []
                access_url = None
                raw_ports = container.attrs["NetworkSettings"]["Ports"]
                if raw_ports:
                    for container_port, bindings in raw_ports.items():
                        if bindings:
                            for binding in bindings:
                                host_port = binding["HostPort"]
                                ports.append(f"{host_port} → {container_port}")
                                if not access_url:
                                    # On utilise le premier port trouvé pour générer une URL
                                    host_ip = request.host.split(":")[0]
                                    access_url = f"http://{host_ip}:{host_port}"

                container_info.append({
                    "name": container.name,
                    "ports": ports,
                    "cpu": f"{cpu_percent:.2f}%",
                    "memory": f"{mem_usage:.2f} MB",
                    "access_url": access_url
                })

        return render_template(
            'admin_dashboard.html',
            users=users,
            services=list(SERVICES.keys()),
            containers=container_info
        )

    # Partie étudiant
    return render_template('student_dashboard.html', user=session['user'], services=list(SERVICES.keys()))


"""Création d’un compte étudiant avec un user_index unique"""
@app.route('/create_user', methods=['POST'])
def create_user():
    if not session.get('admin'):
        return redirect('/')
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT MAX(user_index) FROM users")
    result = c.fetchone()
    next_index = (result[0] or 0) + 1  # Si aucun user, on démarre à 1

    try:
        c.execute("INSERT INTO users (username, password, user_index) VALUES (?, ?, ?)", 
                  (username, password, next_index))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()
    return redirect('/dashboard')


@app.route('/launch/<service_name>')
def launch_service(service_name):
    if 'user' not in session:
        return redirect('/')
    user = session['user']
    service = SERVICES.get(service_name)
    if not service:
        return f"Unknown service: {service_name}", 404

    user_index = get_user_index(user)
    if user_index is None:
        return "User index not found", 500

    now_str = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    server_ip = request.host.split(":")[0]  # récupère l'IP du serveur (ex: 192.168.1.10)
    port = service['port_base'] + user_index
    service_url = f"http://{server_ip}:{port}"
    container_name = f"{service_name}-{user}"
    port = service['port_base'] + user_index
    if not is_port_free(port):
        return f"Port {port} is already in use. Please try again later.", 500

    volume_name = f"vol-{service_name}-{user}"
    network_name = f"net-{service_name}"
    

    # Create Docker network if not exists
    try:
        client.networks.get(network_name)
    except docker.errors.NotFound:
        client.networks.create(network_name, driver="bridge")

    # Remove old container if exists
    try:
        old = client.containers.get(container_name)
        old.remove(force=True)
    except:
        pass

    # Create volume if not exists
    try:
        client.volumes.get(volume_name)
    except:
        client.volumes.create(name=volume_name)

    container = client.containers.run(
        service['image'],
        name=container_name,
        detach=True,
        ports={f"{service['port_internal']}/tcp": port},
        environment=service['env'],
        volumes={volume_name: {'bind': service['volume_path'], 'mode': 'rw'}},
#        hostname=hostname,
        network=network_name,
        restart_policy={"Name": "no"},
        labels={"last_access": now_str})
        
    return render_template('service_ready.html', service_name=service_name, service_url=service_url)
    
@app.route('/admin/delete_session/<username>')
def delete_session(username):
    if not session.get('admin'):
        return redirect('/')
    for container in client.containers.list(all=True):
        if container.name.endswith(f"-{username}"):
            container.remove(force=True)
    
    return redirect('/dashboard')


@app.route('/admin/status/<username>')
def check_status(username):
    if not session.get('admin'):
        return redirect('/')
    user_containers = [c.name for c in client.containers.list() if c.name.endswith(f"-{username}")]
    return {"running_containers": user_containers}


@app.route('/admin/install_package', methods=['POST'])
def install_package():
    if not session.get('admin'):
        return redirect('/')
    container_name = request.form['container']
    package_name = request.form['package']
    try:
        container = client.containers.get(container_name)
        exec_log = container.exec_run(f"apt update && apt install -y {package_name}", user="root")
        return exec_log.output.decode()
    except Exception as e:
        return str(e)




@app.route("/admin/new_service", methods=["GET", "POST"])
def new_service():
    if request.method == "POST":
        # Récupération des champs simples
        name = request.form.get("name")
        image = request.form.get("image")
        port_internal = request.form.get("port_internal")
        port_base = request.form.get("port_base")

        # Validation minimale
        if not name or not image or not port_internal or not port_base:
            flash("All required fields must be filled!", "danger")
            return redirect(request.url)

        # Récupération des volumes
        volumes = request.form.getlist("volumes")

        # Variables d'environnement
        env_keys = request.form.getlist("env_key")
        env_values = request.form.getlist("env_value")
        environment = dict(zip(env_keys, env_values)) if env_keys and env_values else {}

        # Ports supplémentaires
        extra_ports = request.form.getlist("extra_ports")
        extra_ports = [int(p) for p in extra_ports if p.strip().isdigit()]

        # Structure du service à sauvegarder
        service_data = {
            "image": image,
            "port_internal": int(port_internal),
            "port_base": int(port_base),
            "volumes": volumes,
            "environment": environment,
            "extra_ports": extra_ports,
        }

        # Chemin du fichier services.yaml
        services_file = "services.yaml"
        if os.path.exists(services_file):
            with open(services_file, "r") as f:
                all_services = yaml.safe_load(f) or {}
        else:
            all_services = {}

        # Ajout du nouveau service
        all_services[name] = service_data

        # Sauvegarde du fichier YAML
        with open(services_file, "w") as f:
            yaml.dump(all_services, f)

        flash(f"Service '{name}' added successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("new_service.html")


@app.route('/admin/add_service', methods=['POST'])
def add_service():
    if not session.get('admin'):
        return redirect('/')
    name = request.form['name']
    image = request.form['image']
    port_internal = int(request.form['port_internal'])
    port_base = int(request.form['port_base'])
    volume_path = request.form['volume_path']
    SERVICES[name] = {
        "image": image,
        "port_base": port_base,
        "env": {},
        "volume_path": volume_path,
        "port_internal": port_internal
    }
    save_services()  # ← ajout ici

    return redirect('/dashboard')


@app.route('/admin/edit_service/<service_name>', methods=['GET', 'POST'])
def edit_service(service_name):
    if not session.get('admin'):
        return redirect('/')

    if service_name not in SERVICES:
        return "Service not found", 404

    service = SERVICES[service_name]

    # Assurer que les clés existent
    service.setdefault('environment', {})
    service.setdefault('volumes', [])
    service.setdefault('extra_ports', [])

    if request.method == 'POST':
        service['image'] = request.form['image']
        service['port_base'] = int(request.form['port_base'])
        service['port_internal'] = int(request.form['port_internal'])

        # Volumes
        volumes = request.form.getlist('volumes')
        service['volumes'] = [v for v in volumes if v.strip()]

        # Env vars
        environment = {}
        env_keys = request.form.getlist('env_key')
        env_vals = request.form.getlist('env_value')
        for k, v in zip(env_keys, env_vals):
            if k.strip():
                environment[k.strip()] = v.strip()
        service['environment'] = environment

        # Extra ports
        extra_ports = request.form.getlist('extra_ports')
        service['extra_ports'] = [int(p) for p in extra_ports if p.strip().isdigit()]

        save_services()
        return redirect('/dashboard')

    return render_template('edit_service.html', service_name=service_name, service=service)

@app.route('/admin/update_service', methods=['POST'])
def update_service():
    if not session.get('admin'):
        return redirect('/')
    
    name = request.form['name']
    image = request.form['image']
    port_internal = int(request.form['port_internal'])
    port_base = int(request.form['port_base'])
    volume_path = request.form['volume_path']
    
    SERVICES[name] = {
        "image": image,
        "port_base": port_base,
        "env": SERVICES[name].get("env", {}),
        "volume_path": volume_path,
        "port_internal": port_internal
    }
    save_services()  # ← sauvegarde ici
    return redirect('/dashboard')

@app.route('/admin/delete_service', methods=['POST'])
def delete_service():
    if not session.get('admin'):
        return redirect('/')
    service_name = request.form['service_name']
    if service_name in SERVICES:
        del SERVICES[service_name]
        save_services()  # ← ajout ici

    return redirect('/dashboard')


@app.route('/admin/stop_container', methods=['POST'])
def stop_container():
    if not session.get('admin'):
        return redirect('/')
    name = request.form['container']
    try:
        container = client.containers.get(name)
        container.stop()
        return "Stopped"
    except Exception as e:
        return str(e)


@app.route('/admin/restart_container', methods=['POST'])
def restart_container():
    if not session.get('admin'):
        return redirect('/')
    name = request.form['container']
    try:
        container = client.containers.get(name)
        container.restart()
        return "Restarted"
    except Exception as e:
        return str(e)


@app.route('/admin/logs_container', methods=['POST'])
def logs_container():
    if not session.get('admin'):
        return redirect('/')
    name = request.form['container']
    try:
        container = client.containers.get(name)
        return container.logs().decode()
    except Exception as e:
        return str(e)


@app.route('/logout')
def logout():
    user = session.get('user')

    if user:
        # Supprimer tous les conteneurs de ce user
        for container in client.containers.list(all=True):
            if container.name.endswith(f"-{user}"):
                try:
                    container.remove(force=True)
                except:
                    pass
    session.clear()
    return redirect('/')
    
if __name__ == '__main__':
    app.run(debug=True, port=5000)
